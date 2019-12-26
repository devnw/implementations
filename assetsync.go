package implementations

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nortonlifelock/domain"
	"github.com/nortonlifelock/integrations"
	"github.com/nortonlifelock/log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AssetSyncJob implements the Job interface required to run the job
type AssetSyncJob struct {
	Payload *AssetSyncPayload

	// the detection status must be queried for each detection, so we cache them
	detectionStatuses []domain.DetectionStatus

	id          string
	payloadJSON string
	ctx         context.Context
	db          domain.DatabaseConnection
	lstream     log.Logger
	appconfig   domain.Config
	config      domain.JobConfig
	insources   domain.SourceConfig
	outsource   domain.SourceConfig
}

// AssetSyncPayload holds the asset groups to be synced by the job. loaded from the job history Payload
type AssetSyncPayload struct {
	GroupIDs []int `json:"groups"`
}

// buildPayload loads the Payload from the job history into the Payload object
func (job *AssetSyncJob) buildPayload(pjson string) (err error) {
	job.Payload = &AssetSyncPayload{}

	if len(pjson) > 0 {
		err = json.Unmarshal([]byte(pjson), job.Payload)
		if err == nil {
			if len(job.Payload.GroupIDs) == 0 {
				err = fmt.Errorf("did not provide group in Payload")
			}
		}
	} else {
		err = fmt.Errorf("no Payload provided to job")
	}

	return err
}

// Process downloads asset information from a scanner (such as IP/vulnerability detections) and stores it in the database
func (job *AssetSyncJob) Process(ctx context.Context, id string, appconfig domain.Config, db domain.DatabaseConnection, lstream log.Logger, payload string, jobConfig domain.JobConfig, inSource []domain.SourceConfig, outSource []domain.SourceConfig) (err error) {

	var ok bool
	if job.ctx, job.id, job.appconfig, job.db, job.lstream, job.payloadJSON, job.config, job.insources, job.outsource, ok = validInputs(ctx, id, appconfig, db, lstream, payload, jobConfig, inSource, outSource); ok {

		if err = job.buildPayload(job.payloadJSON); err == nil {

			job.lstream.Send(log.Debug("Creating scanner connection..."))

			var vscanner integrations.Vscanner
			if vscanner, err = integrations.NewVulnScanner(job.ctx, job.insources.Source(), job.db, job.lstream, job.appconfig, job.insources); err == nil {

				if job.detectionStatuses, err = job.db.GetDetectionStatuses(); err == nil {
					job.lstream.Send(log.Debug("Scanner connection created, beginning processing..."))

					for _, groupID := range job.Payload.GroupIDs {
						if err = job.createAssetGroupInDB(groupID, job.insources.SourceID()); err == nil {
							job.lstream.Send(log.Infof("started processing %v", groupID))
							job.processGroup(vscanner, groupID)
							job.lstream.Send(log.Infof("finished processing %v", groupID))
						} else {
							job.lstream.Send(log.Error("error while creating asset group", err))
						}
					}
				} else {
					job.lstream.Send(log.Error("error while preloading detection statuses", err))
				}
			} else {
				job.lstream.Send(log.Error("error while creating scanner connection", err))
			}
		} else {
			err = fmt.Errorf("error while building payload - %s", err.Error())
		}
	} else {
		err = fmt.Errorf("input validation failed")
	}

	return err
}

// This method is responsible for gathering the assets of the group, as well as kicking off the threads that process each asset
func (job *AssetSyncJob) processGroup(vscanner integrations.Vscanner, groupID int) {
	var groupIDString = strconv.Itoa(groupID)

	// gather the asset information
	devVulnChan, err := vscanner.Detections(job.ctx, []string{groupIDString})
	if err == nil {

		var comboWg = &sync.WaitGroup{}
		var deviceMap sync.Map

		index := 0

		for {
			if devVulnCombo, ok := <-devVulnChan; ok {

				index++
				if index%100 == 0 {
					comboWg.Wait()
				}

				if asset, err := devVulnCombo.Device(); err == nil {

					var deviceID = sord(asset.SourceID())
					if len(deviceID) > 0 {

						ctx, cancel := context.WithCancel(context.Background())
						deviceCtxInt, loaded := deviceMap.LoadOrStore(deviceID, ctx)
						firstTimeWithDevice := !loaded

						if firstTimeWithDevice {
							comboWg.Add(1)
							go func(deviceID string, asset domain.Device, devVulnCombo domain.Detection, cancel context.CancelFunc) {
								defer comboWg.Done()
								defer handleRoutinePanic(job.lstream)

								err = job.addDeviceInformationToDB(asset, groupID)
								if err != nil {
									job.lstream.Send(log.Errorf(err, "error while adding asset information to the database"))
								}
								cancel()
							}(deviceID, asset, devVulnCombo, cancel)
						}

						if deviceCtx, ok := deviceCtxInt.(context.Context); ok {
							comboWg.Add(1)
							go func(deviceID string, asset domain.Device, devVulnCombo domain.Detection, deviceCtx context.Context) {
								defer comboWg.Done()
								defer handleRoutinePanic(job.lstream)

								<-deviceCtx.Done()
								job.processAsset(deviceID, asset, devVulnCombo, groupID)
							}(deviceID, asset, devVulnCombo, deviceCtx)
						} else {
							job.lstream.Send(log.Error("context failed to load from sync map", err))
						}
					} else {
						job.lstream.Send(log.Error("device passed with id 0", err))
					}

				} else {
					job.lstream.Send(log.Errorf(err, "error while gathering asset information"))
				}

			} else {
				break
			}
		}

		comboWg.Wait()
	} else {
		job.lstream.Send(log.Error("error while grabbing device and vulnerability information", err))
	}
}

// Only process the asset if it has not been processed by another group
func (job *AssetSyncJob) processAsset(deviceID string, asset domain.Device, devVulnCombo domain.Detection, groupID int) {
	var err error

	if len(sord(asset.SourceID())) > 0 {
		var existingDeviceInDb domain.Device
		if existingDeviceInDb, err = job.db.GetDeviceByAssetOrgID(sord(asset.SourceID()), job.config.OrganizationID()); err == nil && existingDeviceInDb != nil {

			if devVulnCombo != nil {
				_ = job.processAssetDetections(existingDeviceInDb, sord(asset.SourceID()), devVulnCombo)
			} else {
				job.lstream.Send(log.Errorf(err, "error while processing asset information in database"))
			}
		} else {
			job.lstream.Send(log.Errorf(fmt.Errorf("could not find device in database for %s", sord(asset.SourceID())), "db error"))
		}
	} else {
		job.lstream.Send(log.Errorf(nil, "empty asset ID gathered from scanner"))
	}
}

// This method creates/gathers the entry for the OS Type as well as updates/creates the asset information in the database
func (job *AssetSyncJob) addDeviceInformationToDB(asset domain.Device, groupID int) (err error) {
	var ostFromDb domain.OperatingSystemType
	if len(asset.OS()) > 0 {
		ostFromDb, err = job.grabAndCreateOsType(asset.OS())
	} else {
		ostFromDb, err = job.grabAndCreateOsType(unknown)
	}

	// this updates asset's OST to the same OST but w/ populated db id
	if err == nil {
		err = job.enterAssetInformationInDB(asset, ostFromDb.ID(), groupID)
		if err != nil {
			job.lstream.Send(log.Error("error while processing asset", err))
		}
	} else {
		job.lstream.Send(log.Error("Couldn't gather database OS information", err))
	}

	return err
}

// this method checks the database to see if an asset under that ip/org and creates an entry if one doesn't exist.
// if an entry exists but does not have an asset id set (which occurs when the CloudSync Job) finds the asset first,
// this method then enters the asset id for that entry
func (job *AssetSyncJob) enterAssetInformationInDB(asset domain.Device, osTypeID int, groupID int) (err error) {
	if asset != nil {

		if len(sord(asset.SourceID())) > 0 {

			var ip = asset.IP()

			var deviceInDB domain.Device
			// first try to find the device in the database using the source asset id
			if deviceInDB, err = job.db.GetDeviceByAssetOrgID(sord(asset.SourceID()), job.config.OrganizationID()); err == nil { // TODO include org id parameter
				if deviceInDB == nil {

					// second we try to find the device in the database using the IP
					if len(asset.IP()) > 0 {
						deviceInDB, err = job.db.GetDeviceByScannerSourceID(ip, groupID, job.config.OrganizationID())
					}
				}

				if err == nil {
					if deviceInDB == nil {

						// TODO currently this procedure just sets IsVirtual to false - how do I find that value?
						_, _, err = job.db.CreateDevice(
							sord(asset.SourceID()),
							job.insources.SourceID(),
							ip,
							asset.HostName(),
							asset.MAC(),
							groupID,
							job.config.OrganizationID(),
							asset.OS(),
							osTypeID,
						)
						if err == nil {
							job.lstream.Send(log.Infof("[+] Device [%v] created", sord(asset.SourceID())))
						} else {
							err = fmt.Errorf(fmt.Sprintf("[-] Error while creating device [%s] - %s", sord(asset.SourceID()), err.Error()))
						}

					} else {

						// this block of code is for when cloud sync job finds the asset before the ASJ does, as the CSJ doesn't set the asset id
						// we also update the os type id because the ASJ will have a more accurate os return
						if len(sord(deviceInDB.SourceID())) == 0 && len(sord(asset.SourceID())) > 0 {
							_, _, err = job.db.UpdateAssetIDOsTypeIDOfDevice(deviceInDB.ID(), sord(asset.SourceID()), job.insources.SourceID(), groupID, asset.OS(), asset.HostName(), osTypeID, job.config.OrganizationID())
							if err == nil {
								job.lstream.Send(log.Infof("Updated device info for asset [%v]", sord(asset.SourceID())))
							} else {
								err = fmt.Errorf(fmt.Sprintf("could not update the asset id for device with ip [%s] - %s", ip, err.Error()))
							}
						} else {
							job.lstream.Send(log.Debugf("DB entry for device [%v] exists, skipping...", sord(asset.SourceID())))
						}
					}
				} else {
					job.lstream.Send(log.Errorf(err, "error while loading device from database"))
				}

			} else {
				job.lstream.Send(log.Errorf(err, "error while loading device from database"))
			}

		} else {
			err = fmt.Errorf("device with id [%s] did not have asset id returned from vuln scanner", sord(asset.SourceID()))
		}

	} else {
		err = fmt.Errorf("improper enterAssetInformationInDB input - nil device passed to process asset")
	}

	return err
}

// This method creates a detection entry in the database for the device/vulnerability combo
// If the detection entry already exists, it increments the amount of times it has been seen by this job by one
// This method is also responsible for gathering detections for the vulnerability
func (job *AssetSyncJob) processAssetDetections(deviceInDb domain.Device, assetID string, vuln domain.Detection) (err error) {
	// the result ID may be concatenated to the end of the vulnerability ID. we chop it off the result from the vulnerability ID with the following line
	vulnID := strings.Split(vuln.VulnerabilityID(), ";")[0]

	var vulnInfo domain.VulnerabilityInfo
	vulnInfo, err = job.db.GetVulnInfoBySourceVulnID(vulnID)
	if err == nil {

		if vulnInfo != nil {

			var exception domain.Ignore
			if exception, err = job.db.GetExceptionByVulnIDOrg(assetID, vulnInfo.SourceVulnID(), job.config.OrganizationID()); err == nil {
				job.createOrUpdateDetection(exception, deviceInDb, vulnInfo, vuln, assetID)
			} else {
				job.lstream.Send(log.Errorf(err, "Error while exceptions device [%v]", assetID))
			}

		} else {
			job.lstream.Send(log.Error("could not find vulnerability in database", fmt.Errorf("[%s] does not have an entry in the database", vulnID)))
		}

	} else {
		job.lstream.Send(log.Errorf(err, "Error while gathering vulnerability info for [%s]", vulnID))
	}

	return err
}

// This method creates a detection entry if one does not exist, and updates the entry if one does
func (job *AssetSyncJob) createOrUpdateDetection(exception domain.Ignore, deviceInDb domain.Device, vulnInfo domain.VulnerabilityInfo, vuln domain.Detection, assetID string) {
	var err error

	var exceptionID string
	if exception != nil {
		exceptionID = exception.ID()
	}

	var detection domain.Detection
	detection, err = job.db.GetDetection(sord(deviceInDb.SourceID()), vulnInfo.ID())
	if err == nil {
		var detectionStatus domain.DetectionStatus
		if detectionStatus = job.getDetectionStatus(vuln.Status()); detectionStatus != nil {
			if detection == nil {
				job.createDetection(vuln, exceptionID, deviceInDb, vulnInfo, assetID, detectionStatus.ID())
			} else {
				_, _, err = job.db.UpdateDetectionTimesSeen(
					sord(deviceInDb.SourceID()),
					vulnInfo.ID(),
					vuln.TimesSeen(),
					detectionStatus.ID(),
				)

				if err == nil {
					job.lstream.Send(log.Infof("Updated detection for device/vuln [%v|%v]", assetID, vulnInfo.ID()))
				} else {
					job.lstream.Send(log.Errorf(err, "Error while updating detection for device/vuln [%v|%v]", assetID, vulnInfo.ID()))
				}
			}
		} else {
			job.lstream.Send(log.Errorf(err, "could not find detection status with name [%s]", vuln.Status()))
		}
	} else {
		job.lstream.Send(log.Debugf("Detection already exists for device/vuln [%v|%v]", assetID, vulnInfo.ID()))
	}
}

// This method creates the detection entry in the database
func (job *AssetSyncJob) createDetection(vuln domain.Detection, exceptionID string, deviceInDb domain.Device, vulnInfo domain.VulnerabilityInfo, assetID string, detectionStatusID int) {
	var err error

	var detected *time.Time
	if detected, err = vuln.Detected(); err == nil {
		if detected != nil {
			if len(exceptionID) == 0 {

				if vuln.ActiveKernel() == nil {
					_, _, err = job.db.CreateDetection(
						job.config.OrganizationID(),
						job.insources.SourceID(),
						sord(deviceInDb.SourceID()),
						vulnInfo.ID(),
						*detected,
						vuln.Proof(),
						vuln.Port(),
						vuln.Protocol(),
						detectionStatusID,
						vuln.TimesSeen(),
					)
				} else {
					_, _, err = job.db.CreateDetectionActiveKernel(
						job.config.OrganizationID(),
						job.insources.SourceID(),
						sord(deviceInDb.SourceID()),
						vulnInfo.ID(),
						*detected,
						vuln.Proof(),
						vuln.Port(),
						vuln.Protocol(),
						iord(vuln.ActiveKernel()),
						detectionStatusID,
						vuln.TimesSeen(),
					)
				}

			} else {

				if vuln.ActiveKernel() == nil {
					_, _, err = job.db.CreateDetectionWithIgnore(
						job.config.OrganizationID(),
						job.insources.SourceID(),
						sord(deviceInDb.SourceID()),
						vulnInfo.ID(),
						exceptionID,
						*detected,
						vuln.Proof(),
						vuln.Port(),
						vuln.Protocol(),
						detectionStatusID,
						vuln.TimesSeen(),
					)
				} else {
					_, _, err = job.db.CreateDetectionWithIgnoreActiveKernel(
						job.config.OrganizationID(),
						job.insources.SourceID(),
						sord(deviceInDb.SourceID()),
						vulnInfo.ID(),
						exceptionID,
						*detected,
						vuln.Proof(),
						vuln.Port(),
						vuln.Protocol(),
						iord(vuln.ActiveKernel()),
						detectionStatusID,
						vuln.TimesSeen(),
					)
				}
			}
		} else {
			err = fmt.Errorf("could not find the time of the detection")
		}

	} else {
		err = fmt.Errorf("error while gathering date of detection - %v", err.Error())
	}

	if err == nil {
		job.lstream.Send(log.Infof("Created detection for device/vuln [%v|%v]", assetID, vulnInfo.ID()))
	} else {
		job.lstream.Send(log.Errorf(err, "Error while creating detection for device/vuln [%v|%v]", assetID, vulnInfo.ID()))
	}
}

func (job *AssetSyncJob) getDetectionStatus(status string) (detectionStatus domain.DetectionStatus) {
	for _, potentialMatch := range job.detectionStatuses {
		if strings.ToLower(status) == strings.ToLower(potentialMatch.Status()) {
			detectionStatus = potentialMatch
			break
		}
	}

	return detectionStatus
}

// This method creates an entry in the database for the operating system type. It then returns the entry so that the id of the OST
// may be used for foreign key references
func (job *AssetSyncJob) grabAndCreateOsType(operatingSystem string) (output domain.OperatingSystemType, err error) {
	if len(operatingSystem) > 0 {
		output, err = job.db.GetOperatingSystemType(operatingSystem)
		if err == nil {
			if output == nil {
				err = fmt.Errorf("could not discern operating system type of [%s]", operatingSystem)
			}
		} else {
			err = fmt.Errorf("(GetOST) %s - [%s]", err.Error(), operatingSystem)
		}
	} else {
		err = fmt.Errorf("operating system sent nil to grabAndCreateOsType")
	}

	return output, err
}

func (job *AssetSyncJob) createAssetGroupInDB(groupID int, sourceID string) (err error) {
	var assetGroup domain.AssetGroup
	if assetGroup, err = job.db.GetAssetGroup(job.config.OrganizationID(), groupID, sourceID); err == nil {
		if assetGroup == nil {
			if _, _, err = job.db.CreateAssetGroup(job.config.OrganizationID(), groupID, sourceID); err == nil {

			} else {
				err = fmt.Errorf("error while creating asset group - %v", err.Error())
			}
		}
	} else {
		err = fmt.Errorf("error while grabbing asset group - %v", err.Error())
	}

	return err
}
