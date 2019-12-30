package implementations

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/nortonlifelock/database/dal"
	"github.com/nortonlifelock/domain"
	"github.com/nortonlifelock/jira"
	"github.com/nortonlifelock/integrations"
	"github.com/nortonlifelock/log"
	"github.com/nortonlifelock/scaffold"
)

// TicketingPayload decides which asset groups to ticket on, as well as defining the min date which is used to calculate the SLA if the calculated
// due date is in the past
type TicketingPayload struct {
	MinDate *time.Time `json:"mindate,omitempty"`
}

// OrgPayload contains the SLA information for how long a vulnerability has to be remediated given the severity
// it is located from the Payload field of the organization table
type OrgPayload struct {
	LowestCVSS  float32       `json:"lowest_ticketed_cvss"`
	CVSSVersion int           `json:"cvss_version"`
	Severities  []OrgSeverity `json:"severities"`
}

const (
	cvssVersion2 = 2
	cvssVersion3 = 3
)

// OrgSeverity holds the information pertaining to the severity and it's relation to CVSS. The severities are organized based on their CVSS minimum score
// CVSSMin dictates the lowest score required for a vulnerability to be associated with this severity. If another severity has a higher CVSS min that
// the vulnerability is also above, the vulnerability is associated with that CVSS min. The duration is the amount of time in days that a remediator would
// have to fix the vulnerability after discovery
type OrgSeverity struct {
	Name     string  `json:"name"`
	Duration int     `json:"duration"`
	CVSSMin  float32 `json:"cvss_min"`
}

// Len implements the sort interface so the severities may be organized
func (payload *OrgPayload) Len() int {
	return len(payload.Severities)
}

// Less identifies which severity entry has a lower CVSS minimum
func (payload *OrgPayload) Less(i, j int) bool {
	return payload.Severities[i].CVSSMin < payload.Severities[j].CVSSMin
}

// Swap swaps two severity entries
func (payload *OrgPayload) Swap(i, j int) {
	payload.Severities[i], payload.Severities[j] = payload.Severities[j], payload.Severities[i]
}

// Validate ensures there is a severity description for an organization, sorts them, and ensures all the numerical values
// held are valid
// additionally, it checks that the cvss version is set within the organization payload
func (payload *OrgPayload) Validate() (valid bool) {
	if len(payload.Severities) > 0 {
		sort.Sort(payload)

		var allNonZero = true
		for _, entry := range payload.Severities {
			if entry.CVSSMin < 0 || entry.Duration < 0 {
				allNonZero = false
				break
			}
		}

		if allNonZero {

			var noOverlap = true
			for index := range payload.Severities {
				if index > 0 {
					if payload.Severities[index].CVSSMin <= payload.Severities[index-1].CVSSMin {
						noOverlap = false
					}
				}
			}

			if noOverlap {
				valid = payload.CVSSVersion == cvssVersion2 || payload.CVSSVersion == cvssVersion3
			}
		}
	}

	return valid
}

// TicketingJob implements the IJob interface required to run the job
type TicketingJob struct {
	Payload *TicketingPayload

	ticketMutex     *sync.Mutex
	ticketingEngine integrations.TicketingEngine
	duplicatesMap   sync.Map

	// TODO: remove the port flag from the code, these should always create multiple tickets
	OrgPayload *OrgPayload

	id          string
	payloadJSON string
	ctx         context.Context
	db          domain.DatabaseConnection
	lstream     log.Logger
	appconfig   domain.Config
	config      domain.JobConfig
	insource    domain.SourceConfig
	outsource   domain.SourceConfig

	cachedReportedBy string
}

// vulnerabilityPayload is passed through the pipeline of the ticketing job
type vulnerabilityPayload struct {
	// ticketing engine is cached in order for multiple threads to share a connection
	tickets integrations.TicketingEngine

	// the organization code is used in the ticket and must be pulled from the database, so it is cached
	orgCode string

	combo domain.Detection
	// device, vuln, and detectedDate are pulled off combo using Accessor methods, but are cached to prevent repeated error checking
	device       domain.Device
	vuln         domain.Vulnerability
	detectedDate *time.Time

	// holds the statuses that are used to query existing tickets when checking for duplicates
	statuses map[string]bool

	// ticket is populated at the end of the process for creation in the ticketing engine
	ticket domain.Ticket
}

// Tag mapping options
const (
	// Append states that the tag mapping information should be included in addition to the information from the scanner
	Append = "Append"

	// Overwrite states that the tag mapping information should replace the information from the scanner
	Overwrite = "Overwrite"
)

// buildPayload loads the Payload from the job history into the Payload object
func (ticketing *TicketingJob) buildPayload(pjson string) (err error) {

	if len(pjson) > 0 {

		ticketing.Payload = &TicketingPayload{}
		ticketing.ticketMutex = &sync.Mutex{}

		err = json.Unmarshal([]byte(pjson), ticketing.Payload)
	} else {
		err = errors.New("Payload length is 0")
	}

	return err
}

func (ticketing *TicketingJob) buildOrgPayload(org domain.Organization) (err error) {
	if len(org.Payload()) > 0 {
		ticketing.OrgPayload = &OrgPayload{}

		err = json.Unmarshal([]byte(org.Payload()), ticketing.OrgPayload)
		if err == nil {
			if !ticketing.OrgPayload.Validate() {
				err = fmt.Errorf("organization payload validation failed")
			}
		}
	} else {
		err = errors.New("Payload length is 0")
	}

	return err
}

// Process the ticketing job loads device information from a scanner, and creates a ticket for each device/vulnerability combination where one does not
// already exist. First, it checks for an entry in the ignore table to see if that device/vulnerability combination is a known exception or false positive
func (ticketing *TicketingJob) Process(ctx context.Context, id string, appconfig domain.Config, db domain.DatabaseConnection, lstream log.Logger, payload string, jobConfig domain.JobConfig, inSource []domain.SourceConfig, outSource []domain.SourceConfig) (err error) {

	var ok bool
	if ticketing.ctx, ticketing.id, ticketing.appconfig, ticketing.db, ticketing.lstream, ticketing.payloadJSON, ticketing.config, ticketing.insource, ticketing.outsource, ok = validInputs(ctx, id, appconfig, db, lstream, payload, jobConfig, inSource, outSource); ok {

		if err = ticketing.buildPayload(ticketing.payloadJSON); err == nil {

			var org domain.Organization
			if org, err = ticketing.db.GetOrganizationByID(ticketing.config.OrganizationID()); err == nil {
				var vscanner integrations.Vscanner
				if vscanner, err = integrations.NewVulnScanner(ticketing.ctx, ticketing.insource.Source(), ticketing.db, ticketing.lstream, ticketing.appconfig, ticketing.insource); vscanner != nil && err == nil {
					if org != nil {

						// the organization Payload holds the SLA configuration
						err = ticketing.buildOrgPayload(org)
						if err == nil {

							ticketing.lstream.Send(log.Debug("Scanner connection initialized."))

							// TODO do we want to cross reference against JIRA, or should we just check our db for the ticket entry?
							var detections []domain.Detection
							if detections, err = ticketing.db.GetDetectionsAfter(tord1970(ticketing.config.LastJobStart()), ticketing.config.OrganizationID()); err == nil {
								ticketing.processVulnerabilities(vscanner, pushDetectionsToChannel(ticketing.ctx, detections))
							} else {
								ticketing.lstream.Send(log.Error("Error occurred while loading device vulnerability information", err))
							}
						} else {
							ticketing.lstream.Send(log.Error("error while processing the organization Payload", err))
						}

					} else {
						ticketing.lstream.Send(log.Errorf(nil, "Null org object returned."))
					}
				} else {
					err = fmt.Errorf("error while creating the vuln scanner: [%v]", err)
				}
			} else {
				err = fmt.Errorf("could not find organization by this ID: [%s] - %s", ticketing.config.OrganizationID(), err.Error())
				ticketing.lstream.Send(log.Error("Error while getting organization.", err))
			}
		} else {
			err = fmt.Errorf("error while building payload - %s", err.Error())
		}
	} else {
		err = fmt.Errorf("input validation failed")
	}

	return err
}

// processVulnerabilities creates a pipeline of channels. each method takes a channel as an input, and creates a channel as an output
// the first pipe in the pipeline is process vulnerability, and the final pipe is create ticket. each method takes an input
// from a channel, performs some transformation on the input, and pushes the result on the output channel for the next method
// to handle
func (ticketing *TicketingJob) processVulnerabilities(vscanner integrations.Vscanner, in <-chan domain.Detection) {
	ticketing.createTicket(
		ticketing.prepareTicketCreation(
			ticketing.findTicketExceptions(
				ticketing.checkIfDeviceIsDecommissioned(
					ticketing.checkForExistingTicket(
						ticketing.processVulnerability(in))),
			),
		),
	)
}

func (ticketing *TicketingJob) processVulnerability(in <-chan domain.Detection) <-chan *vulnerabilityPayload {
	defer handleRoutinePanic(ticketing.lstream)
	var out = make(chan *vulnerabilityPayload)

	go func() {
		defer handleRoutinePanic(ticketing.lstream)
		defer close(out)
		wg := &sync.WaitGroup{}

		var orgcode = ticketing.getOrgCode()
		var err error

		ticketing.lstream.Send(log.Debugf("Opening connection to job engine for Job ID [%v].", ticketing.id))
		var tickets integrations.TicketingEngine
		if tickets, err = integrations.GetEngine(ticketing.ctx, ticketing.outsource.Source(), ticketing.db, ticketing.lstream, ticketing.appconfig, ticketing.outsource); err == nil {
			ticketing.lstream.Send(log.Debugf("Connection opened to job engine for Job ID [%v].", ticketing.id))
			ticketing.ticketingEngine = tickets

			for {
				if item, ok := <-in; ok {
					wg.Add(1)
					go func(dvCombo domain.Detection) {
						defer wg.Done()
						defer handleRoutinePanic(ticketing.lstream)

						if strings.ToLower(dvCombo.Status()) != strings.ToLower(domain.Fixed) {
							var err error

							var device domain.Device
							var vuln domain.Vulnerability
							var detectedDate *time.Time

							device, err = dvCombo.Device()
							if err == nil {
								vuln, err = dvCombo.Vulnerability()
								if err == nil {
									detectedDate, err = dvCombo.Detected()
								}
							}

							if err == nil {
								if device != nil && vuln != nil && detectedDate != nil {
									if ticketing.getCVSSScore(vuln) >= ticketing.OrgPayload.LowestCVSS {

										statuses := make(map[string]bool)
										loadStatuses(tickets, statuses)

										ticketing.lstream.Send(log.Infof("Processing vulnerability [%s] on device [%v]", vuln.SourceID(), sord(device.SourceID())))

										var payload = &vulnerabilityPayload{
											tickets,
											orgcode,
											dvCombo,
											device,
											vuln,
											detectedDate,
											statuses,
											nil,
										}

										select {
										case <-ticketing.ctx.Done():
											return
										case out <- payload:
										}
									} else {
										ticketing.lstream.Send(log.Debugf("Skipping vulnerability [%s] on device [%v] with CVSS [%v].", vuln.SourceID(), sord(device.SourceID()), ticketing.getCVSSScore(vuln)))
									}
								} else {
									ticketing.lstream.Send(log.Errorf(err, "failed to load vulnerability information for [%v|%v|%v]", sord(device.SourceID()), vuln.SourceID(), detectedDate))
								}
							} else {
								ticketing.lstream.Send(log.Errorf(err, "error while processing vulnerability %v", dvCombo.VulnerabilityID()))
							}
						} else {
							// vulnerability fixed - don't create ticket
						}
					}(item)

				} else {
					break
				}
			}
			wg.Wait()
		} else {
			ticketing.lstream.Send(log.Error("Error while getting job object.", err))
		}
	}()

	return out
}

func (ticketing *TicketingJob) getOrgCode() (orgCode string) {
	if len(ticketing.config.OrganizationID()) > 0 {

		// Get the organization from the database using the id in the ticket object
		if org, err := ticketing.db.GetOrganizationByID(ticketing.config.OrganizationID()); err == nil {
			// Ensure there is only one return
			if org != nil {
				orgCode = org.Code()
			} else {
				ticketing.lstream.Send(log.Criticalf(err, "failed to load the organization for ID [%v]", ticketing.config.OrganizationID()))
			}
		}
	}
	return orgCode
}

func loadStatuses(tickets integrations.TicketingEngine, statuses map[string]bool) {
	// Statuses to Query when looking for existing tickets for the vulnerabilities

	// TODO TODO do we want these hardcoded or configurable?
	statuses[tickets.GetStatusMap(jira.StatusOpen)] = true
	statuses[tickets.GetStatusMap(jira.StatusReopened)] = true
	statuses[tickets.GetStatusMap(jira.StatusResolvedRemediated)] = true
	statuses[tickets.GetStatusMap(jira.StatusResolvedDecom)] = true
	statuses[tickets.GetStatusMap(jira.StatusResolvedException)] = true
	statuses[tickets.GetStatusMap(jira.StatusResolvedFalsePositive)] = true
	statuses[tickets.GetStatusMap(jira.StatusClosedCerf)] = true

	// TODO: Remove this once the closed-error status is part of exceptions
	statuses[tickets.GetStatusMap(jira.StatusClosedError)] = true
}

func (ticketing *TicketingJob) checkForExistingTicket(in <-chan *vulnerabilityPayload) <-chan *vulnerabilityPayload {
	defer handleRoutinePanic(ticketing.lstream)

	var out = make(chan *vulnerabilityPayload)
	go func() {
		defer handleRoutinePanic(ticketing.lstream)
		defer close(out)
		wg := &sync.WaitGroup{}

		for {

			var payload *vulnerabilityPayload
			var ok bool

			select {
			case <-ticketing.ctx.Done():
				return
			case payload, ok = <-in:
				// do nothing
			}

			if ok {

				var port int
				var protocol string

				port = payload.combo.Port()
				protocol = payload.combo.Protocol()

				var keyToPreventDuplicates = fmt.Sprintf("%v-%v-%v-%v", sord(payload.device.SourceID()), payload.vuln.SourceID(), port, protocol)

				var exists bool
				if _, exists = ticketing.duplicatesMap.LoadOrStore(keyToPreventDuplicates, true); !exists { // doesn't exist in sync map

					wg.Add(1)
					go func(payload *vulnerabilityPayload, exists bool, port int, protocol string) {
						defer handleRoutinePanic(ticketing.lstream)
						defer wg.Done()

						var err error

						var existingTicket domain.TicketSummary
						if existingTicket, err = ticketing.db.GetTicketByDeviceIDVulnID(sord(payload.device.SourceID()), payload.vuln.ID(), ticketing.config.OrganizationID()); err == nil { // TODO is this vuln ID correct? I would be happiest if the device lookup didn't use the source id
							if existingTicket == nil {

								var existingTicketChan <-chan domain.Ticket
								var statuses = make(map[string]bool)
								statuses["Open"] = true
								statuses["In-Progress"] = true
								statuses["Reopened"] = true
								statuses["Resolved-Remediated"] = true
								statuses["Resolved-FalsePositive"] = true
								statuses["Resolved-Decommissioned"] = true
								statuses["Resolved-Exception"] = true
								existingTicketChan, err = ticketing.ticketingEngine.GetTicketsByDeviceIDVulnID(ticketing.insource.Source(), payload.orgCode, sord(payload.device.SourceID()), payload.vuln.SourceID(), statuses, payload.combo.Port(), payload.combo.Protocol())
								if err == nil {

									if emptyChannel(existingTicketChan) {
										ticketing.lstream.Send(log.Infof("No ticket found for vulnerability [%s] on device [%v]. Creating new ticket...", payload.vuln.SourceID(), sord(payload.device.SourceID())))
										select {
										case <-ticketing.ctx.Done():
											return
										case out <- payload:
										}
									}
								} else {
									ticketing.lstream.Send(log.Error(
										fmt.Sprintf(
											"Error issues from JIRA with vuln title [%v] and ID [%v].",
											payload.vuln.Name(),
											payload.vuln.SourceID(),
										),
										err,
									))
								}

							} else {
								ticketing.lstream.Send(log.Info(
									fmt.Sprintf(
										"EXISTING TICKET: [%v] for vulnerability [%v] with Vuln ID [%v] on device [%v]. Skipping...",
										existingTicket.Title(),
										payload.vuln.Name(),
										payload.vuln.SourceID(),
										sord(payload.device.SourceID()),
									)))
							}
						} else {
							ticketing.lstream.Send(log.Warning(
								fmt.Sprintf(
									"Error getting issues from database with vuln title [%v] and ID [%v].",
									payload.vuln.Name(),
									payload.vuln.SourceID(),
								),
								err,
							))
						}
					}(payload, exists, port, protocol)
				} else {
					ticketing.lstream.Send(log.Info(
						fmt.Sprintf(
							"ALREADY PROCESSED: A ticket was already created for vulnerability [%v] with Vuln ID [%v] on device [%v] during this run. Skipping...",
							payload.vuln.Name(),
							payload.vuln.SourceID(),
							sord(payload.device.SourceID()),
						)))
				}

			} else {
				break
			}

		}

		wg.Wait()
	}()

	return out
}

func emptyChannel(in <-chan domain.Ticket) bool {
	for {
		select {
		case _, ok := <-in:
			if ok {
				go func() {
					for {
						if _, ok := <-in; !ok {
							return
						}
					}
				}()
				return false
			} else {
				return true
			}
		}
	}
}

func (ticketing *TicketingJob) checkIfDeviceIsDecommissioned(in <-chan *vulnerabilityPayload) <-chan *vulnerabilityPayload {
	defer handleRoutinePanic(ticketing.lstream)
	var out = make(chan *vulnerabilityPayload)

	go func() {
		defer handleRoutinePanic(ticketing.lstream)
		defer close(out)
		wg := &sync.WaitGroup{}

		var deviceDecommMap sync.Map
		var deviceIDToMutex sync.Map

		for {
			var payload *vulnerabilityPayload
			var ok bool

			select {
			case <-ticketing.ctx.Done():
				return
			case payload, ok = <-in:
				// do nothing
			}

			if ok {

				wg.Add(1)
				go func(payload *vulnerabilityPayload) {
					defer handleRoutinePanic(ticketing.lstream)
					defer wg.Done()

					var err error

					decommMutexInterface, _ := deviceIDToMutex.LoadOrStore(sord(payload.device.SourceID()), &sync.Mutex{})
					decommMutex, ok := decommMutexInterface.(*sync.Mutex)
					if !ok {
						// this block should never hit, as *sync.Mutex are the only things stored
						decommMutex = &sync.Mutex{}
						ticketing.lstream.Send(log.Errorf(err, "failed to load the mutex for device [%s]", sord(payload.device.SourceID())))
					}

					decommTime, err := ticketing.checkForDecommOnDevice(decommMutex, deviceDecommMap, payload)

					/*
						The value held within the variable decommTime dictates the devices relation to a decommission entry in the Ignore table

						nil value
							should not occur at this point, and only occurs as a return value of the loading of the decommission entry failed
							checkForDecommOnDevice knows that it needs to load a decommTime if the function loads a nil value from deviceDecommMap

						zero value
							means there is no decommission entry in the ignore table for the device

						non-zero value
							means there is a decommission entry in the ignore table for the device
							if the alert date of the vuln occurs before the decommission date, there is no need for alarm and no need to ticket on the device as it is likely offline
							if the alert date of the vuln occurs after the decommission date, the device was falsely marked as decommissioned and is actually online
					*/
					ticketing.pushPayloadIfNotDecommissioned(decommTime, err, out, payload)

				}(payload)
			} else {
				break
			}
		}

		wg.Wait()
	}()

	return out
}

func (ticketing *TicketingJob) pushPayloadIfNotDecommissioned(decommTime *time.Time, err error, out chan *vulnerabilityPayload, payload *vulnerabilityPayload) {
	if decommTime != nil && err == nil {
		if decommTime.IsZero() {
			// the decommission time means there is no decommission entry in the ignore table for the device
			select {
			case <-ticketing.ctx.Done():
				return
			case out <- payload:
			}
		} else if payload.detectedDate.After(*decommTime) {
			// we found a vulnerability that occurred after the device was marked as decommissioned
			// we drop a critical log, and then push the dev/vuln combo onto the channel as we want to ticket it
			ticketing.lstream.Send(log.Criticalf(nil, "Device [%s] WAS marked as decommissioned, but a vulnerability [%s] was discovered after the decommissioned date [%s|%s]",
				sord(payload.device.SourceID()), payload.vuln.SourceID(), payload.detectedDate, *decommTime))
			select {
			case <-ticketing.ctx.Done():
				return
			case out <- payload:
			}
		} else {
			// we found a vulnerability from before an asset was decommissioned - therefore we don't want to ticket as the device is
			// likely offline

			// this block is intentionally left empty
		}
	} else {
		// this block should only hit if there was an error while loading the decommission entry from the ignore table
		// we can't be sure if it's decommissioned or not,
		ticketing.lstream.Send(log.Errorf(err, "failed to load the potential decommissioned date for device [%s]", sord(payload.device.SourceID())))
		select {
		case <-ticketing.ctx.Done():
			return
		case out <- payload:
		}
	}
}

func (ticketing *TicketingJob) checkForDecommOnDevice(decommMutex *sync.Mutex, deviceDecommMap sync.Map, payload *vulnerabilityPayload) (decommTime *time.Time, err error) {
	defer handleRoutinePanic(ticketing.lstream)
	decommMutex.Lock()
	defer decommMutex.Unlock()

	decommTimeInt, _ := deviceDecommMap.LoadOrStore(sord(payload.device.SourceID()), nil)
	decommTime, _ = decommTimeInt.(*time.Time)
	if decommTime == nil {
		ticketing.lstream.Send(log.Infof("Checking if device [%s] was marked as decommissioned", sord(payload.device.SourceID())))

		var decommIgnoreEntry domain.Ignore
		if decommIgnoreEntry, err = ticketing.db.HasDecommissioned(sord(payload.device.SourceID()), ticketing.insource.SourceID(), ticketing.config.OrganizationID()); err == nil {
			if decommIgnoreEntry != nil { // we found a decommission entry in the ignore table - mark the device id as decommissioned
				dd := tord(decommIgnoreEntry.DueDate())
				decommTime = &dd
			} else {
				decommTime = &time.Time{}
			}
			deviceDecommMap.Store(sord(payload.device.SourceID()), decommTime)
		} else {
			ticketing.lstream.Send(log.Error("error while loading decommissions", err))
		}
	}

	return decommTime, err
}

// checks for exceptions and false positives for the ticket before creation
func (ticketing *TicketingJob) findTicketExceptions(in <-chan *vulnerabilityPayload) <-chan *vulnerabilityPayload {
	defer handleRoutinePanic(ticketing.lstream)
	var out = make(chan *vulnerabilityPayload)

	go func() {
		defer handleRoutinePanic(ticketing.lstream)
		defer close(out)
		wg := &sync.WaitGroup{}

		for {

			var payload *vulnerabilityPayload
			var ok bool

			select {
			case <-ticketing.ctx.Done():
				return
			case payload, ok = <-in:
				// do nothing
			}

			if ok {

				wg.Add(1)
				go func(payload *vulnerabilityPayload) {
					defer handleRoutinePanic(ticketing.lstream)
					defer wg.Done()

					var err error

					ticketing.lstream.Send(log.Infof("Searching for exception for vulnerability [%s] on device [%v]", payload.vuln.SourceID(), sord(payload.device.SourceID())))

					var exceptions []domain.Ignore
					port := payload.combo.Port()
					protocol := payload.combo.Protocol()
					servicePort := "" // TODO: Remove the port duplication code

					if port >= 0 && port <= 65535 && len(protocol) > 0 {

						var portText string
						portText = strconv.Itoa(port)

						servicePort = fmt.Sprintf("%s %s", portText, protocol)

					}

					if exceptions, err = ticketing.db.HasExceptionOrFalsePositive(ticketing.insource.SourceID(), payload.vuln.SourceID(), sord(payload.device.SourceID()), ticketing.config.OrganizationID(), servicePort, payload.device.OS()); err == nil {
						if len(exceptions) <= 0 {

							select {
							case <-ticketing.ctx.Done():
								return
							case out <- payload:
							}

						} else {
							ticketing.lstream.Send(log.Info(
								fmt.Sprintf(
									"Exception exists or False positive [%s]: vulnerability [%s] with Vuln ID [%s] on device [%v]. Skipping...",
									exceptions[0].ID(),
									payload.vuln.Name(),
									payload.vuln.SourceID(),
									sord(payload.device.SourceID()),
								)))
						}
					} else {
						ticketing.lstream.Send(log.Error(
							fmt.Sprintf(
								"Error while getting exceptions [%v] with Vuln ID [%v] on device [%v]",
								payload.vuln.Name(),
								payload.vuln.SourceID(),
								sord(payload.device.SourceID()),
							),
							err,
						))
					}
				}(payload)
			} else {
				break
			}
		}

		wg.Wait()
	}()

	return out
}

// takes the Payload and transforms it to a ticket. overwrites/appends information in the ticket fields from cloud service tags if a tag mapping & tags
// for the device are found
func (ticketing *TicketingJob) prepareTicketCreation(in <-chan *vulnerabilityPayload) <-chan *vulnerabilityPayload {
	defer handleRoutinePanic(ticketing.lstream)
	var out = make(chan *vulnerabilityPayload)

	go func() {
		defer handleRoutinePanic(ticketing.lstream)
		defer close(out)
		wg := &sync.WaitGroup{}

		for {

			var payload *vulnerabilityPayload
			var ok bool

			select {
			case <-ticketing.ctx.Done():
				return
			case payload, ok = <-in:
				// do nothing
			}

			if ok {

				wg.Add(1)
				go func(payload *vulnerabilityPayload) {
					defer handleRoutinePanic(ticketing.lstream)
					defer wg.Done()

					var err error
					payload.ticket = &dal.Ticket{}
					var create bool
					payload.ticket, create = ticketing.payloadToTicket(payload)
					if create {
						// map cloud service fields to ticket if necessary
						err = ticketing.handleCloudTagMappings(payload.ticket)
						if err != nil {
							// we still want to create the ticket, but log the error
							ticketing.lstream.Send(log.Errorf(err, "error while managing job mappings for [%s]", payload.ticket.Title()))
						}

						select {
						case <-ticketing.ctx.Done():
							return
						case out <- payload:
						}
					} else {
						ticketing.lstream.Send(log.Infof("Skipping vulnerability with CVSS [%f]", payload.vuln.CVSS2()))
					}
				}(payload)
			} else {
				break
			}
		}

		wg.Wait()
	}()

	return out
}

func (ticketing *TicketingJob) createTicket(in <-chan *vulnerabilityPayload) {
	defer handleRoutinePanic(ticketing.lstream)

	var wg = &sync.WaitGroup{}
	for {

		payload, ok := <-in
		if ok {

			if payload != nil {

				if len(payload.ticket.VulnerabilityID()) > 0 {
					wg.Add(1)
					go func(payload *vulnerabilityPayload) {
						defer handleRoutinePanic(ticketing.lstream)
						defer wg.Done()
						ticketing.createIndividualTicket(payload)
					}(payload)
				} else {
					var err = errors.Errorf("%s had an invalid vulnerability id in createTicket", payload.ticket.VulnerabilityID())
					ticketing.lstream.Send(log.Error(err.Error(), err))
				}
			} else {
				var err = errors.Errorf("Ticket received NIL from channel in createTicket | %v", payload)
				ticketing.lstream.Send(log.Error(err.Error(), err))
			}

		} else {
			break
		}
	}
	wg.Wait()
}

func (ticketing *TicketingJob) calculateSLA(vuln domain.Vulnerability, alertDate time.Time) (priority string, dueDate time.Time, create bool) {
	severity := ticketing.getSLAForVuln(vuln)
	if severity != nil {
		create = true
		priority = severity.Name
		dueDate = ticketing.calculateDueDate(alertDate, severity.Duration)
	}

	return priority, dueDate, create
}

func (ticketing *TicketingJob) getSLAForVuln(vuln domain.Vulnerability) (highestApplicableSeverity *OrgSeverity) {
	var cvssScore = ticketing.getCVSSScore(vuln)

	// we iterate over the sorted list of custom severity ranges and find the highest applicable severity
	for index := range ticketing.OrgPayload.Severities {
		if cvssScore >= ticketing.OrgPayload.Severities[index].CVSSMin {
			highestApplicableSeverity = &ticketing.OrgPayload.Severities[index]
		}
	}

	return highestApplicableSeverity
}

func (ticketing *TicketingJob) calculateDueDate(alertDate time.Time, durationInDays int) (dueDate time.Time) {
	dueDate = alertDate.AddDate(0, 0, durationInDays)

	if ticketing.Payload.MinDate != nil {
		var minDate = ticketing.Payload.MinDate.AddDate(0, 0, durationInDays)
		if dueDate.Before(minDate) {
			dueDate = minDate
		}
	}

	return dueDate
}

func (ticketing *TicketingJob) createIndividualTicket(payload *vulnerabilityPayload) {
	if _, ticketTitle, err := ticketing.ticketingEngine.CreateTicket(payload.ticket); err == nil {

		if len(ticketTitle) > 0 {
			ticketing.lstream.Send(log.Info(
				fmt.Sprintf(
					"Ticket created for vulnerability [%s] on device [%v]. [Title: %s]",
					payload.ticket.VulnerabilityID(),
					payload.ticket.DeviceID(),
					ticketTitle,
				)))

			// track the created ticket in our database
			_, _, err = ticketing.db.CreateTicket(
				ticketTitle,
				jira.StatusOpen,
				payload.combo.ID(),
				ticketing.config.OrganizationID(),
				tord(payload.ticket.DueDate()),
				time.Now(),
				tord(nil),
			)

			if err != nil {
				ticketing.lstream.Send(log.Errorf(err, "error while creating database entry for ticket [%v]", ticketTitle))
			}
		} else {
			ticketing.lstream.Send(log.Error(
				fmt.Sprintf(
					"Could not retrieve ticket title created for vulnerability [%s] with vuln ID [%v] on device [%v]",
					*payload.ticket.VulnerabilityTitle(),
					payload.ticket.VulnerabilityID(),
					payload.ticket.DeviceID(),
				),
				err,
			))
		}
	} else {
		ticketing.lstream.Send(log.Error(
			fmt.Sprintf(
				"Error while creating ticket for vulnerability [%s] with Vuln ID [%v] on device [%v]",
				*payload.ticket.VulnerabilityTitle(),
				payload.ticket.VulnerabilityID(),
				payload.ticket.DeviceID(),
			),
			err,
		))
	}
}

// takes a Payload for a ticket and transforms it to a dal ticket for creation
func (ticketing *TicketingJob) payloadToTicket(payload *vulnerabilityPayload) (newtix *dal.Ticket, create bool) {

	// Handle address fields
	var macs string
	var hosts string
	var ips string
	macs, ips, hosts = ticketing.gatherHostInfoFromDevice(payload)

	// Handle the assignment using the data in config which is the scanner assignment for the IPs
	// TODO: Update this to be specific to the out source as well so we can use different job engines
	var assignmentGroup = ""
	if ag, err := ticketing.db.GetAssignmentGroupByIP(ticketing.insource.SourceID(), ticketing.config.OrganizationID(), ips); err == nil {
		if ag != nil && len(ag) > 0 {
			assignmentGroup = ag[0].GroupName()
		}
	} else {
		ticketing.lstream.Send(log.Errorf(err, "error while loading assignment group for device [%s]", ips))
	}

	// Determine Due Date and Priority
	var duedate time.Time
	var alertdate = time.Now()
	if payload.detectedDate != nil {
		alertdate = *payload.detectedDate
	}
	var priority string
	priority, duedate, create = ticketing.calculateSLA(payload.vuln, alertdate)
	if create {

		cves, vendorRefs := ticketing.gatherReferences(payload)
		var configs string
		if len(vendorRefs) == 0 {
			// Anything other than CVE should be as a config vuln
			configs = "True"
		}

		// TODO: This needs to be updated to a better method in the next releases
		var servicePorts string
		if payload.combo.Port() >= 0 && payload.combo.Port() <= 65535 && len(payload.combo.Protocol()) > 0 {
			servicePorts = fmt.Sprintf("%d %s", payload.combo.Port(), payload.combo.Protocol())
		}

		var ticketType = "Request"
		var operatingSystem = ticketing.gatherOSDropdown(payload.device.OS())

		// TODO make configurable
		var summary = fmt.Sprintf("Aegis (%s - %s): %s", ips, hosts, payload.vuln.Name())

		var template *scaffold.Template
		template = scaffold.NewTemplateEmpty()
		template.UpdateBase(descriptionTemplate)
		template.Repl("%vulnurl", "").
			Repl("%scandate", alertdate.Format(time.RFC1123Z)).
			Repl("%description", payload.vuln.Description()).
			Repl("%proof", payload.combo.Proof())

		var description = template.Get()
		var solution = removeHTMLTags(ticketing.gatherSolution(payload))
		var methodOfDiscovery = ticketing.insource.Source()
		var vulnerabilityTitle = payload.vuln.Name()
		var cvss = ticketing.getCVSSScore(payload.vuln)
		var fullOSName = payload.device.OS()
		var reportedBy = ticketing.getCachedReportedBy()

		newtix = &dal.Ticket{
			DeviceIDvar: sord(payload.device.SourceID()),
			//GroupIDvar:           strconv.Itoa(ticketing.Payload.DeviceGroup), // TODO
			VulnerabilityIDvar:   payload.vuln.SourceID(),
			MethodOfDiscoveryvar: &methodOfDiscovery,

			Descriptionvar:        &description,
			Summaryvar:            &summary,
			Solutionvar:           &solution,
			VulnerabilityTitlevar: &vulnerabilityTitle,
			CVSSvar:               &cvss,

			OSDetailedvar:      &fullOSName,
			OperatingSystemvar: &operatingSystem,
			MacAddressvar:      &macs,
			IPAddressvar:       &ips,
			HostNamevar:        &hosts,

			ReportedByvar:      &reportedBy,
			TicketTypevar:      &ticketType,
			OrganizationIDvar:  ticketing.config.OrganizationID(),
			AssignmentGroupvar: &assignmentGroup,
			Priorityvar:        &priority,

			Configsvar:          configs,
			ServicePortsvar:     &servicePorts,
			VendorReferencesvar: &vendorRefs,
			CVEReferencesvar:    &cves,

			AlertDatevar: &alertdate,
			DueDatevar:   &duedate,
			OrgCodevar:   &payload.orgCode,
		}
	}

	return newtix, create
}

func (ticketing *TicketingJob) gatherSolution(payload *vulnerabilityPayload) (solution string) {

	ctx, cancel := context.WithCancel(ticketing.ctx)
	defer cancel()

	sols, err := payload.vuln.Solutions(ctx)
	if err == nil {
		for {
			select {
			case <-ticketing.ctx.Done():
				return
			case sol, ok := <-sols:
				if ok {
					solution = sol.String()
				}

				return
			}
		}
	} else {
		ticketing.lstream.Send(log.Errorf(err, "error while gathering solution for vulnerability %s", payload.vuln.SourceID()))
	}

	return solution
}

func (ticketing *TicketingJob) gatherReferences(payload *vulnerabilityPayload) (cves string, vendorRefs string) {
	refs, err := payload.vuln.References(ticketing.ctx)
	if err == nil {
		func() {
			for {
				select {
				case <-ticketing.ctx.Done():
					return
				case ref, ok := <-refs:
					if ok {
						if strings.Contains(ref.Reference(), "CVE") {
							cves += ref.Reference() + ","
						} else {
							vendorRefs += ref.Reference() + ","
						}
					} else {
						return
					}
				}
			}
		}()

		cves = strings.TrimRight(cves, ",")
		vendorRefs = strings.TrimRight(vendorRefs, ",")
	} else {
		ticketing.lstream.Send(log.Errorf(err, "error while gathering references for vulnerability %v", payload.vuln.SourceID()))
	}

	return cves, vendorRefs
}

func (ticketing *TicketingJob) gatherHostInfoFromDevice(payload *vulnerabilityPayload) (string, string, string) {
	var macs = payload.device.MAC()
	var hosts = payload.device.HostName()
	var ips = payload.device.IP()

	return macs, ips, hosts
}

// the cloud sync job pulls tag information from cloud service providers. we can use that tag information to overwrite JIRA fields or append
// the information to a JIRA field
func (ticketing *TicketingJob) handleCloudTagMappings(tic domain.Ticket) (err error) {
	if len(sord(tic.IPAddress())) > 0 {
		var ips = strings.Split(sord(tic.IPAddress()), ",")

		var device domain.Device
		device, err = ticketing.getDeviceByIPList(ips)

		if err == nil {
			if device != nil { // device with ip found in database, check for it's tags

				// tag maps are org specific
				var tagMaps []domain.TagMap // tag maps say which cloud tag should be matched to which ticket field
				tagMaps, err = ticketing.db.GetTagMapsByOrg(ticketing.config.OrganizationID())

				if err == nil {
					if len(tagMaps) > 0 {

						// grab all the cloud tags for a device
						var tagsForDevice []domain.Tag
						tagsForDevice, err = ticketing.db.GetTagsForDevice(device.ID())
						if err == nil {
							err = ticketing.mapAllTagsForDevice(tic, tagsForDevice, tagMaps)
						} else {
							err = fmt.Errorf("error while grabbing tags for device [%s] - %s", device.ID(), err.Error())
						}

					}
				} else {
					err = fmt.Errorf("error while grabbing tag maps - %s", err.Error())
				}
			} else {
				// TODO no device found in db - email warning
				ticketing.lstream.Send(log.Warningf(nil, "could not find device with any of ips [%s]", sord(tic.IPAddress())))
			}
		} else {
			err = fmt.Errorf("error while grabbing device - %s", err.Error())
		}

	} else {
		err = fmt.Errorf("ticket [%s] did not have an associated IP", tic.Title())
	}

	return err
}

// this ticket takes all tags found for a particular device, and maps them to fields within the domain.Ticket if necessary
func (ticketing *TicketingJob) mapAllTagsForDevice(tic domain.Ticket, tagsForDevice []domain.Tag, tagMaps []domain.TagMap) (err error) {
	for index := range tagsForDevice {
		tagForDevice := tagsForDevice[index]

		var tagForDeviceKey domain.TagKey
		tagForDeviceKey, err = ticketing.db.GetTagKeyByID(strconv.Itoa(tagForDevice.TagKeyID()))
		if err == nil {
			if tagForDeviceKey != nil {
				err = ticketing.mapTagForDevice(tic, tagForDeviceKey, tagForDevice, tagMaps)
				if err != nil {
					break
				}
			} else {
				err = fmt.Errorf("could not find tag key [%d] in the database", tagForDevice.TagKeyID())
				break
			}
		} else {
			err = fmt.Errorf("error while grabbing tag key from database - %s", err.Error())
			break
		}
	}

	return err
}

// check to see if the tags found for a ticket match any of the fields in the tag map
// a tag map associates a JIRA field to a cloud service tag
func (ticketing *TicketingJob) mapTagForDevice(tic domain.Ticket, tagForDeviceKey domain.TagKey, tagForDevice domain.Tag, tagMaps []domain.TagMap) (err error) {
	for mapIndex := range tagMaps {
		tagMap := tagMaps[mapIndex]

		// see if the cloud tag is mapped to a job field
		if strings.ToLower(strings.ToLower(tagMap.CloudTag())) == strings.ToLower(tagForDeviceKey.KeyValue()) {
			var ticketKey = tagMap.TicketingTag()

			var option = tagMap.Options()
			if tagMap.Options() == Append || tagMap.Options() == Overwrite {

				tic = tagMappedTicket{
					tic,
					strings.ToLower(ticketKey),
					option,
					tagForDevice,
					tagMap.CloudTag(),
					sord(tic.HostName()),
					sord(tic.AssignmentGroup()),
					sord(tic.Labels()),
				}
			} else {
				err = fmt.Errorf("unrecognized tag mapping option: %s", tagMap.Options())
				ticketing.lstream.Send(log.Error("mapping error", err))
			}
		}
	}

	return err
}

type tagMappedTicket struct {
	domain.Ticket
	ticketKeyLower string
	option         string
	tagForDevice   domain.Tag
	cloudTag       string

	hostname        string
	assignmentGroup string
	labels          string
}

func (tmt tagMappedTicket) HostName() *string {
	val := tmt.hostname
	if tmt.option == Append && len(tmt.hostname) > 0 {
		val = fmt.Sprintf("%s,%s", tmt.hostname, tmt.tagForDevice.Value())
	} else { //overwrite
		val = tmt.tagForDevice.Value()
	}
	return &val
}

func (tmt tagMappedTicket) AssignmentGroup() *string {
	val := tmt.assignmentGroup
	if tmt.option == Append && len(tmt.assignmentGroup) > 0 {
		val = fmt.Sprintf("%s,%s", tmt.assignmentGroup, tmt.tagForDevice.Value())
	} else { //overwrite
		val = tmt.tagForDevice.Value()
	}
	return &val
}

func (tmt tagMappedTicket) Labels() *string {
	val := fmt.Sprintf("%s-%s", strings.ToLower(tmt.cloudTag), tmt.tagForDevice.Value())

	if tmt.option == Append && len(tmt.labels) > 0 {
		val = fmt.Sprintf("%s,%s", tmt.labels, val)
	}
	return &val
}

func (ticketing *TicketingJob) getDeviceByIPList(ips []string) (device domain.Device, err error) {
	for index := range ips {
		ip := ips[index]

		device, err = ticketing.db.GetDeviceByIP(ip, ticketing.config.OrganizationID())
		if err == nil {
			if device != nil {
				break
			}
		} else {
			break
		}
	}

	return device, err
}

// transforms the specific OS from the scanner and transforms it to a generic OS that can be chosen in a dropdown field
func (ticketing *TicketingJob) gatherOSDropdown(input string) (output string) {
	var ost domain.OperatingSystemType
	var err error
	if ost, err = ticketing.db.GetOperatingSystemType(input); err == nil {
		output = ost.Type()
	} else {
		output = unknown
		ticketing.lstream.Send(log.Errorf(err, "error while loading operating system type for [%s]", input))
	}

	return output
}

const (
	descriptionTemplate = `
	*Scan Data:*

	Scan Date: %scandate

	*Description:*
	%description

	*Proof:*
	%proof
	`
)

var reportedByMutex sync.Mutex

func (ticketing *TicketingJob) getCachedReportedBy() (reportedBy string) {

	if len(ticketing.cachedReportedBy) > 0 {
		reportedBy = ticketing.cachedReportedBy
	} else {
		reportedByMutex.Lock()
		defer reportedByMutex.Unlock()

		var parseReporter domain.BasicAuth
		var err error
		if err = json.Unmarshal([]byte(ticketing.outsource.AuthInfo()), &parseReporter); err == nil {
			if len(parseReporter.Username) > 0 {
				reportedBy = parseReporter.Username
				ticketing.cachedReportedBy = reportedBy
			} else {
				err = fmt.Errorf("could not parse the reported from the source config")
			}
		}

		if err != nil {
			ticketing.lstream.Send(log.Error("could not find the reporter from the out source config", err))
		}
	}

	return reportedBy
}

func (ticketing *TicketingJob) getCVSSScore(vuln domain.Vulnerability) (score float32) {
	if ticketing.OrgPayload.CVSSVersion == cvssVersion3 && vuln.CVSS3() != nil {
		score = *vuln.CVSS3()
	} else {
		score = vuln.CVSS2()
	}

	return score
}

func pushDetectionsToChannel(ctx context.Context, detections []domain.Detection) <-chan domain.Detection {
	out := make(chan domain.Detection)
	go func() {
		defer close(out)

		for _, detection := range detections {
			select {
			case <-ctx.Done():
				return
			case out <- detection:
			}
		}
	}()

	return out
}
