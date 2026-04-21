package service

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"x-ui/core"
	"x-ui/logger"
	"x-ui/util/sys"
	"x-ui/xray"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

type ProcessState string

const (
	Running ProcessState = "running"
	Stop    ProcessState = "stop"
	Error   ProcessState = "error"
)

type Status struct {
	T   time.Time `json:"-"`
	Cpu float64   `json:"cpu"`
	Mem struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"mem"`
	Swap struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"swap"`
	Disk struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"disk"`
	Xray    CoreStatus `json:"xray"`
	Singbox CoreStatus `json:"singbox"`
	Uptime   uint64    `json:"uptime"`
	Loads    []float64 `json:"loads"`
	TcpCount int       `json:"tcpCount"`
	UdpCount int       `json:"udpCount"`
	NetIO    struct {
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	} `json:"netIO"`
	NetTraffic struct {
		Sent uint64 `json:"sent"`
		Recv uint64 `json:"recv"`
	} `json:"netTraffic"`
}

type Release struct {
	TagName string `json:"tag_name"`
}

type coreReleaseSpec struct {
	apiURL        string
	downloadURL   string
	archiveName   string
	archiveFormat string
	binaryName    string
}

type ServerService struct {
	xrayService XrayService
}

func (s *ServerService) GetStatus(lastStatus *Status) *Status {
	now := time.Now()
	status := &Status{
		T: now,
	}

	percents, err := cpu.Percent(0, false)
	if err != nil {
		logger.Warning("get cpu percent failed:", err)
	} else {
		status.Cpu = percents[0]
	}

	upTime, err := host.Uptime()
	if err != nil {
		logger.Warning("get uptime failed:", err)
	} else {
		status.Uptime = upTime
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		logger.Warning("get virtual memory failed:", err)
	} else {
		status.Mem.Current = memInfo.Used
		status.Mem.Total = memInfo.Total
	}

	swapInfo, err := mem.SwapMemory()
	if err != nil {
		logger.Warning("get swap memory failed:", err)
	} else {
		status.Swap.Current = swapInfo.Used
		status.Swap.Total = swapInfo.Total
	}

	distInfo, err := disk.Usage("/")
	if err != nil {
		logger.Warning("get dist usage failed:", err)
	} else {
		status.Disk.Current = distInfo.Used
		status.Disk.Total = distInfo.Total
	}

	avgState, err := load.Avg()
	if err != nil {
		logger.Warning("get load avg failed:", err)
	} else {
		status.Loads = []float64{avgState.Load1, avgState.Load5, avgState.Load15}
	}

	ioStats, err := net.IOCounters(false)
	if err != nil {
		logger.Warning("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		ioStat := ioStats[0]
		status.NetTraffic.Sent = ioStat.BytesSent
		status.NetTraffic.Recv = ioStat.BytesRecv

		if lastStatus != nil {
			duration := now.Sub(lastStatus.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(status.NetTraffic.Sent-lastStatus.NetTraffic.Sent) / seconds)
			down := uint64(float64(status.NetTraffic.Recv-lastStatus.NetTraffic.Recv) / seconds)
			status.NetIO.Up = up
			status.NetIO.Down = down
		}
	} else {
		logger.Warning("can not find io counters")
	}

	status.TcpCount, err = sys.GetTCPCount()
	if err != nil {
		logger.Warning("get tcp connections failed:", err)
	}

	status.UdpCount, err = sys.GetUDPCount()
	if err != nil {
		logger.Warning("get udp connections failed:", err)
	}

	status.Xray = s.xrayService.GetCoreStatus(core.Xray)
	status.Singbox = s.xrayService.GetCoreStatus(core.SingBox)

	return status
}

func (s *ServerService) GetCoreVersions(coreType core.Type) ([]string, error) {
	url := "https://gh-proxy.org/https://api.github.com/repos/XTLS/Xray-core/releases"
	if coreType == core.SingBox {
		url = "https://gh-proxy.org/https://api.github.com/repos/SagerNet/sing-box/releases"
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if err = ensureSuccessfulResponse(resp); err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(make([]byte, 8192))
	buffer.Reset()
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}

	releases := make([]Release, 0)
	err = json.Unmarshal(buffer.Bytes(), &releases)
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(releases))
	for _, release := range releases {
		versions = append(versions, release.TagName)
	}
	return versions, nil
}

func (s *ServerService) downloadCore(coreType core.Type, version string) (string, *coreReleaseSpec, error) {
	spec, err := s.getCoreReleaseSpec(coreType, version)
	if err != nil {
		return "", nil, err
	}
	resp, err := http.Get(spec.downloadURL)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if err = ensureSuccessfulResponse(resp); err != nil {
		return "", nil, err
	}

	fileName := spec.archiveName
	_ = os.Remove(fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", nil, err
	}

	return fileName, spec, nil
}

func (s *ServerService) downloadXRay(version string) (string, error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	switch osName {
	case "darwin":
		osName = "macos"
	}

	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	}

	fileName := fmt.Sprintf("Xray-%s-%s.zip", osName, arch)
	url := fmt.Sprintf("https://gh-proxy.org/https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, fileName)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err = ensureSuccessfulResponse(resp); err != nil {
		return "", err
	}

	os.Remove(fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

func (s *ServerService) UpdateCore(coreType core.Type, version string) error {
	switch coreType {
	case core.Xray:
		return s.UpdateXray(version)
	case core.SingBox:
		return s.UpdateSingbox(version)
	default:
		return errors.New("unknown core type")
	}
}

func (s *ServerService) UpdateXray(version string) error {
	zipFileName, err := s.downloadXRay(version)
	if err != nil {
		return err
	}

	zipFile, err := os.Open(zipFileName)
	if err != nil {
		return err
	}
	defer func() {
		zipFile.Close()
		os.Remove(zipFileName)
	}()

	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return err
	}

	_ = s.xrayService.StopCore(core.Xray)
	defer func() {
		err := s.xrayService.RestartCore(core.Xray, true)
		if err != nil {
			logger.Error("start xray failed:", err)
		}
	}()

	copyZipFile := func(zipName string, fileName string) error {
		zipFile, err := reader.Open(zipName)
		if err != nil {
			return err
		}
		os.Remove(fileName)
		file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, fs.ModePerm)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(file, zipFile)
		return err
	}

	err = copyZipFile("xray", xray.GetBinaryPath())
	if err != nil {
		return err
	}
	err = copyZipFile("geosite.dat", xray.GetGeositePath())
	if err != nil {
		return err
	}
	err = copyZipFile("geoip.dat", xray.GetGeoipPath())
	if err != nil {
		return err
	}

	return nil

}

func (s *ServerService) UpdateSingbox(version string) error {
	archiveName, spec, err := s.downloadCore(core.SingBox, version)
	if err != nil {
		return err
	}

	defer func() {
		_ = os.Remove(archiveName)
	}()

	_ = s.xrayService.StopCore(core.SingBox)
	defer func() {
		err := s.xrayService.RestartCore(core.SingBox, true)
		if err != nil {
			logger.Error("start sing-box failed:", err)
		}
	}()

	switch spec.archiveFormat {
	case "tar.gz":
		return s.extractTarGzBinary(archiveName, spec.binaryName, core.GetBinaryPath(core.SingBox))
	case "zip":
		return s.extractZipBinary(archiveName, spec.binaryName, core.GetBinaryPath(core.SingBox))
	default:
		return fmt.Errorf("unsupported archive format: %s", spec.archiveFormat)
	}
}

func (s *ServerService) getCoreReleaseSpec(coreType core.Type, version string) (*coreReleaseSpec, error) {
	switch coreType {
	case core.Xray:
		return nil, errors.New("xray uses legacy updater path")
	case core.SingBox:
		return getSingboxReleaseSpec(version)
	default:
		return nil, errors.New("unknown core type")
	}
}

func getSingboxReleaseSpec(version string) (*coreReleaseSpec, error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	switch arch {
	case "amd64", "arm64":
	default:
		return nil, fmt.Errorf("sing-box online install does not support arch %s", arch)
	}

	format := "tar.gz"
	if osName == "windows" {
		format = "zip"
	}
	if osName != "linux" && osName != "darwin" && osName != "windows" {
		return nil, fmt.Errorf("sing-box online install does not support os %s", osName)
	}

	if strings.HasPrefix(version, "v") {
		version = strings.TrimPrefix(version, "v")
	}

	archiveName := fmt.Sprintf("sing-box-%s-%s-%s.%s", version, osName, arch, format)
	if format == "zip" {
		archiveName = fmt.Sprintf("sing-box-%s-%s-%s.zip", version, osName, arch)
	}

	return &coreReleaseSpec{
		apiURL:        "https://gh-proxy.org/https://api.github.com/repos/SagerNet/sing-box/releases",
		downloadURL:   fmt.Sprintf("https://gh-proxy.org/https://github.com/SagerNet/sing-box/releases/download/v%s/%s", version, archiveName),
		archiveName:   archiveName,
		archiveFormat: format,
		binaryName:    binaryNameForOS("sing-box", osName),
	}, nil
}

func binaryNameForOS(name string, osName string) string {
	if osName == "windows" {
		return name + ".exe"
	}
	return name
}

func (s *ServerService) extractZipBinary(archivePath string, zipName string, fileName string) error {
	zipFile, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return err
	}

	for _, file := range reader.File {
		if filepath.Base(file.Name) != zipName {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeExecutable(fileName, rc)
	}

	return fmt.Errorf("binary %s not found in archive", zipName)
}

func (s *ServerService) extractTarGzBinary(archivePath string, binaryName string, fileName string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(header.Name) != binaryName {
			continue
		}
		return writeExecutable(fileName, tarReader)
	}

	return fmt.Errorf("binary %s not found in archive", binaryName)
}

func writeExecutable(fileName string, reader io.Reader) error {
	_ = os.Remove(fileName)
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, fs.ModePerm)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err = io.Copy(file, reader); err != nil {
		return err
	}
	return os.Chmod(fileName, 0755)
}

func ensureSuccessfulResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("download failed: %s", resp.Status)
}
