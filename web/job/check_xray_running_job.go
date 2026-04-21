package job

import (
	"x-ui/core"
	"x-ui/web/service"
)

type CheckXrayRunningJob struct {
	xrayService service.XrayService
	checkTime   map[core.Type]int
}

func NewCheckXrayRunningJob() *CheckXrayRunningJob {
	return &CheckXrayRunningJob{
		checkTime: map[core.Type]int{},
	}
}

func (j *CheckXrayRunningJob) Run() {
	for _, coreType := range j.xrayService.GetManagedCoreTypes() {
		if j.xrayService.IsCoreRunning(coreType) {
			j.checkTime[coreType] = 0
			continue
		}
		j.checkTime[coreType]++
		if j.checkTime[coreType] < 2 {
			continue
		}
		j.xrayService.SetCoreToNeedRestart(coreType)
	}
}
