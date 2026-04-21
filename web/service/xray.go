package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"x-ui/core"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/xray"

	"go.uber.org/atomic"
)

var (
	processes = map[core.Type]*core.Process{}
	results   = map[core.Type]string{}
	lock      sync.Mutex

	restartFlags = map[core.Type]*atomic.Bool{
		core.Xray:    &atomic.Bool{},
		core.SingBox: &atomic.Bool{},
	}
)

type CoreStatus struct {
	Name     string       `json:"name"`
	Type     string       `json:"type"`
	State    ProcessState `json:"state"`
	ErrorMsg string       `json:"errorMsg"`
	Version  string       `json:"version"`
}

type XrayService struct {
	inboundService InboundService
	settingService SettingService
}

func (s *XrayService) IsCoreRunning(coreType core.Type) bool {
	p := processes[coreType]
	return p != nil && p.IsRunning()
}

func (s *XrayService) IsXrayRunning() bool {
	return s.IsCoreRunning(core.Xray)
}

func (s *XrayService) IsAnyCoreRunning() bool {
	return s.IsCoreRunning(core.Xray) || s.IsCoreRunning(core.SingBox)
}

func (s *XrayService) GetCoreName(coreType core.Type) string {
	if coreType == core.SingBox {
		return "sing-box"
	}
	return "xray"
}

func (s *XrayService) GetCoreErr(coreType core.Type) error {
	if processes[coreType] == nil {
		return nil
	}
	return processes[coreType].GetErr()
}

func (s *XrayService) GetCoreResult(coreType core.Type) string {
	if results[coreType] != "" {
		return results[coreType]
	}
	if s.IsCoreRunning(coreType) {
		return ""
	}
	if processes[coreType] == nil {
		return ""
	}
	results[coreType] = processes[coreType].GetResult()
	return results[coreType]
}

func (s *XrayService) GetCoreVersion(coreType core.Type) string {
	if processes[coreType] == nil {
		return "Unknown"
	}
	return processes[coreType].GetVersion()
}

func (s *XrayService) GetCoreStatus(coreType core.Type) CoreStatus {
	status := CoreStatus{
		Name:    s.GetCoreName(coreType),
		Type:    string(coreType),
		Version: s.GetCoreVersion(coreType),
	}
	if s.IsCoreRunning(coreType) {
		status.State = Running
		return status
	}
	if err := s.GetCoreErr(coreType); err != nil {
		status.State = Error
	} else {
		status.State = Stop
	}
	status.ErrorMsg = s.GetCoreResult(coreType)
	return status
}

func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	inbounds, err := s.getEnabledInboundsByCore(core.Xray)
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inbound.GenXrayInboundConfig())
	}
	return xrayConfig, nil
}

func (s *XrayService) GetSingboxConfig() (map[string]interface{}, error) {
	templateConfig, err := s.settingService.GetSingboxConfigTemplate()
	if err != nil {
		return nil, err
	}

	singboxConfig := map[string]interface{}{}
	err = json.Unmarshal([]byte(templateConfig), &singboxConfig)
	if err != nil {
		return nil, err
	}

	rawInbounds, ok := singboxConfig["inbounds"].([]interface{})
	if !ok {
		rawInbounds = make([]interface{}, 0)
	}

	inbounds, err := s.getEnabledInboundsByCore(core.SingBox)
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		inboundConfig, convErr := inbound.GenSingboxInboundConfig()
		if convErr != nil {
			return nil, fmt.Errorf("convert inbound %s:%d to sing-box failed: %w", inbound.Remark, inbound.Port, convErr)
		}
		rawInbounds = append(rawInbounds, inboundConfig)
	}
	singboxConfig["inbounds"] = rawInbounds
	return singboxConfig, nil
}

func (s *XrayService) buildRuntimeConfig(coreType core.Type) ([]byte, int, error) {
	switch coreType {
	case core.SingBox:
		cfg, err := s.GetSingboxConfig()
		if err != nil {
			return nil, 0, err
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		return data, 0, err
	default:
		cfg, err := s.GetXrayConfig()
		if err != nil {
			return nil, 0, err
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return nil, 0, err
		}
		return data, getXrayAPIPort(cfg), nil
	}
}

func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, error) {
	if !s.IsXrayRunning() {
		return nil, errors.New("xray is not running")
	}
	return processes[core.Xray].GetTraffic(true)
}

func (s *XrayService) RestartCore(coreType core.Type, isForce bool) error {
	configBytes, apiPort, err := s.buildRuntimeConfig(coreType)
	if err != nil {
		return err
	}

	p := processes[coreType]
	if p != nil && p.IsRunning() {
		if !isForce && core.EqualConfigBytes(p.ConfigBytes(), configBytes) {
			logger.Debugf("not need to restart core %s", coreType)
			return nil
		}
		_ = p.Stop()
	}

	processes[coreType] = core.NewProcess(coreType, configBytes, apiPort)
	results[coreType] = ""
	return processes[coreType].Start()
}

func (s *XrayService) RestartAll(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()

	errs := make([]error, 0)
	for _, coreType := range []core.Type{core.Xray, core.SingBox} {
		if err := s.RestartCore(coreType, isForce); err != nil {
			errs = append(errs, err)
		}
	}
	return combineErrors(errs)
}

func (s *XrayService) StopCore(coreType core.Type) error {
	lock.Lock()
	defer lock.Unlock()

	if s.IsCoreRunning(coreType) {
		return processes[coreType].Stop()
	}
	return errors.New("core is not running")
}

func (s *XrayService) StopAll() error {
	lock.Lock()
	defer lock.Unlock()

	errs := make([]error, 0)
	for _, coreType := range []core.Type{core.Xray, core.SingBox} {
		if p := processes[coreType]; p != nil && p.IsRunning() {
			if err := p.Stop(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return combineErrors(errs)
}

func (s *XrayService) SetCoreToNeedRestart(coreType core.Type) {
	if flag := restartFlags[coreType]; flag != nil {
		flag.Store(true)
	}
}

func (s *XrayService) SetToNeedRestart() {
	s.SetCoreToNeedRestart(core.Xray)
	s.SetCoreToNeedRestart(core.SingBox)
}

func (s *XrayService) IsCoreNeedRestartAndSetFalse(coreType core.Type) bool {
	if flag := restartFlags[coreType]; flag != nil {
		return flag.CAS(true, false)
	}
	return false
}

func (s *XrayService) GetManagedCoreTypes() []core.Type {
	return []core.Type{core.Xray, core.SingBox}
}

func (s *XrayService) getEnabledInboundsByCore(coreType core.Type) ([]*model.Inbound, error) {
	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	result := make([]*model.Inbound, 0)
	for _, inbound := range inbounds {
		if !inbound.Enable || inbound.GetCoreType() != coreType {
			continue
		}
		result = append(result, inbound)
	}
	return result, nil
}

func getXrayAPIPort(cfg *xray.Config) int {
	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag == "api" {
			return inbound.Port
		}
	}
	return 0
}

func combineErrors(errs []error) error {
	filtered := make([]error, 0)
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return fmt.Errorf("%v", filtered)
}
