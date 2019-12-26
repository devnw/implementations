package implementations

import (
	"github.com/nortonlifelock/job"
	"sync"
)

const (
	rescanJob      = "RescanJob"
	rescanQueueJob = "RescanQueueJob"
	ticketingJob   = "TicketingJob"
	exceptionJob   = "ExceptionJob"
	scanSyncJob    = "ScanSyncJob"
	scanCloseJob   = "ScanCloseJob"
	bulkUpdateJob  = "BulkUpdateJob"
	vulnSyncJob    = "VulnSyncJob"
	cloudSyncJob   = "CloudSyncJob"
	assetSyncJob   = "AssetSyncJob"
	cisRescanJob   = "CISRescanJob"
	ticketSyncJob  = "TicketSyncJob"
	cloudDecomJob  = "CloudDecommissionJob"
)

var oneRegister = sync.Once{}

func init() {
	oneRegister.Do(func() {
		job.Register(rescanJob, &RescanJob{})
		job.Register(rescanQueueJob, &RescanQueueJob{})
		job.Register(ticketingJob, &TicketingJob{})
		job.Register(exceptionJob, &ExceptionJob{})
		job.Register(scanSyncJob, &ScanSyncJob{})
		job.Register(scanCloseJob, &ScanCloseJob{})
		job.Register(bulkUpdateJob, &BulkUpdateJob{})
		job.Register(assetSyncJob, &AssetSyncJob{})
		job.Register(vulnSyncJob, &VulnSyncJob{})
		job.Register(cloudSyncJob, &CloudSyncJob{})
		job.Register(cisRescanJob, &CISRescanJob{})
		job.Register(ticketSyncJob, &TicketSyncJob{})
		job.Register(cloudDecomJob, &CloudDecommissionJob{})
	})
}
