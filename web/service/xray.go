package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
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

const (
	hy2SelfSignedServerName = "www.bing.com"
	hy2SelfSignedCertPath   = "bin/hy2-selfsigned.crt"
	hy2SelfSignedKeyPath    = "bin/hy2-selfsigned.key"
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

func (s *XrayService) IsCoreInstalled(coreType core.Type) bool {
	_, err := os.Stat(core.GetBinaryPath(coreType))
	return err == nil
}

func (s *XrayService) GetInstalledCoreTypes() []core.Type {
	result := make([]core.Type, 0)
	for _, coreType := range s.GetManagedCoreTypes() {
		if s.IsCoreInstalled(coreType) {
			result = append(result, coreType)
		}
	}
	if len(result) == 0 {
		return []core.Type{core.Xray}
	}
	return result
}

func (s *XrayService) GetDefaultInstalledCoreType() core.Type {
	coreTypes := s.GetInstalledCoreTypes()
	if len(coreTypes) == 0 {
		return core.Xray
	}
	return coreTypes[0]
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
		if convErr = ensureSingboxInboundTLS(inbound, inboundConfig); convErr != nil {
			return nil, fmt.Errorf("prepare sing-box inbound %s:%d failed: %w", inbound.Remark, inbound.Port, convErr)
		}
		rawInbounds = append(rawInbounds, inboundConfig)
	}
	singboxConfig["inbounds"] = rawInbounds
	return singboxConfig, nil
}

func ensureSingboxInboundTLS(inbound *model.Inbound, inboundConfig map[string]interface{}) error {
	if inbound.Protocol != model.Hysteria2 {
		return nil
	}

	stream := map[string]interface{}{}
	if inbound.StreamSettings != "" {
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err != nil {
			return err
		}
	}

	tlsObj, _ := inboundConfig["tls"].(map[string]interface{})
	if tlsObj == nil {
		tlsObj = map[string]interface{}{"enabled": true}
		inboundConfig["tls"] = tlsObj
	}

	tlsSettings, _ := stream["tlsSettings"].(map[string]interface{})
	serverName, _ := tlsObj["server_name"].(string)
	if serverName == "" && tlsSettings != nil {
		serverName, _ = tlsSettings["serverName"].(string)
	}
	if serverName == "" {
		serverName = hy2SelfSignedServerName
	}
	tlsObj["server_name"] = serverName

	if hasSingboxCertificate(tlsObj) {
		return nil
	}

	certPath, keyPath, err := ensureHy2SelfSignedCertFiles(serverName)
	if err != nil {
		return err
	}
	tlsObj["certificate_path"] = certPath
	tlsObj["key_path"] = keyPath
	return nil
}

func hasSingboxCertificate(tlsObj map[string]interface{}) bool {
	for _, key := range []string{"certificate_path", "key_path"} {
		if value, ok := tlsObj[key].(string); ok && value != "" {
			return true
		}
	}
	for _, key := range []string{"certificate", "key"} {
		switch value := tlsObj[key].(type) {
		case string:
			if value != "" {
				return true
			}
		case []string:
			if len(value) > 0 {
				return true
			}
		case []interface{}:
			if len(value) > 0 {
				return true
			}
		}
	}
	return false
}

func ensureHy2SelfSignedCertFiles(serverName string) (string, string, error) {
	if _, err := os.Stat(hy2SelfSignedCertPath); err == nil {
		if _, keyErr := os.Stat(hy2SelfSignedKeyPath); keyErr == nil {
			return hy2SelfSignedCertPath, hy2SelfSignedKeyPath, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(hy2SelfSignedCertPath), 0o755); err != nil {
		return "", "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   serverName,
			Organization: []string{"x-ui hy2 self-signed"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err = os.WriteFile(hy2SelfSignedCertPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err = os.WriteFile(hy2SelfSignedKeyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return hy2SelfSignedCertPath, hy2SelfSignedKeyPath, nil
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
