package core

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
	"x-ui/util/common"
	"x-ui/xray"

	"github.com/Workiva/go-datastructures/queue"
	statsservice "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
)

type Type string

const (
	Xray    Type = "xray"
	SingBox Type = "sing-box"
)

var (
	trafficRegex = regexp.MustCompile("(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)")
	versionRegex = regexp.MustCompile(`\d+\.\d+\.\d+(?:[-+._A-Za-z0-9]*)?`)
)

func GetBinaryName(coreType Type) string {
	return fmt.Sprintf("%s-%s-%s", coreType, runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath(coreType Type) string {
	return "bin/" + GetBinaryName(coreType)
}

func GetConfigPath(coreType Type) string {
	name := strings.ReplaceAll(string(coreType), "-", "_")
	return fmt.Sprintf("bin/%s_config.json", name)
}

func GetGeositePath() string {
	return "bin/geosite.dat"
}

func GetGeoipPath() string {
	return "bin/geoip.dat"
}

type Process struct {
	coreType    Type
	cmd         *exec.Cmd
	version     string
	apiPort     int
	configBytes []byte
	lines       *queue.Queue
	exitErr     error
}

func NewProcess(coreType Type, configBytes []byte, apiPort int) *Process {
	p := &Process{
		coreType:    coreType,
		version:     "Unknown",
		apiPort:     apiPort,
		configBytes: append([]byte(nil), configBytes...),
		lines:       queue.New(100),
	}
	runtime.SetFinalizer(p, func(proc *Process) {
		_ = proc.Stop()
	})
	return p
}

func (p *Process) CoreType() Type {
	return p.coreType
}

func (p *Process) ConfigBytes() []byte {
	return append([]byte(nil), p.configBytes...)
}

func (p *Process) IsRunning() bool {
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	return p.cmd.ProcessState == nil
}

func (p *Process) GetErr() error {
	return p.exitErr
}

func (p *Process) GetResult() string {
	if p.lines.Empty() && p.exitErr != nil {
		return p.exitErr.Error()
	}
	items, _ := p.lines.TakeUntil(func(item interface{}) bool {
		return true
	})
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, item.(string))
	}
	return strings.Join(lines, "\n")
}

func (p *Process) GetVersion() string {
	return p.version
}

func (p *Process) refreshVersion() {
	args := []string{"-version"}
	if p.coreType == SingBox {
		args = []string{"version"}
	}
	cmd := exec.Command(GetBinaryPath(p.coreType), args...)
	data, err := cmd.Output()
	if err != nil {
		p.version = "Unknown"
		return
	}
	match := versionRegex.Find(data)
	if len(match) == 0 {
		p.version = strings.TrimSpace(string(data))
		return
	}
	p.version = string(match)
}

func (p *Process) Start() (err error) {
	if p.IsRunning() {
		return fmt.Errorf("%s is already running", p.coreType)
	}

	defer func() {
		if err != nil {
			p.exitErr = err
		}
	}()

	configPath := GetConfigPath(p.coreType)
	err = os.WriteFile(configPath, p.configBytes, fs.ModePerm)
	if err != nil {
		return common.NewErrorf("write %s config failed: %v", p.coreType, err)
	}

	args := []string{"-c", configPath}
	if p.coreType == SingBox {
		args = []string{"run", "-c", configPath}
	}
	cmd := exec.Command(GetBinaryPath(p.coreType), args...)
	p.cmd = cmd

	stdReader, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	errReader, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	readPipe := func(reader *bufio.Reader, closer interface{ Close() error }) {
		defer func() {
			common.Recover("")
			_ = closer.Close()
		}()
		for {
			line, _, readErr := reader.ReadLine()
			if readErr != nil {
				return
			}
			if p.lines.Len() >= 100 {
				p.lines.Get(1)
			}
			p.lines.Put(string(line))
		}
	}

	go readPipe(bufio.NewReaderSize(stdReader, 8192), stdReader)
	go readPipe(bufio.NewReaderSize(errReader, 8192), errReader)

	go func() {
		runErr := cmd.Run()
		if runErr != nil {
			p.exitErr = runErr
		}
	}()

	p.refreshVersion()
	return nil
}

func (p *Process) Stop() error {
	if !p.IsRunning() {
		return errors.New("process is not running")
	}
	return p.cmd.Process.Kill()
}

func (p *Process) GetTraffic(reset bool) ([]*xray.Traffic, error) {
	if p.coreType != Xray {
		return nil, errors.New("traffic statistics are only supported for xray core")
	}
	if p.apiPort == 0 {
		return nil, common.NewError("xray api port wrong:", p.apiPort)
	}
	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%v", p.apiPort), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := statsservice.NewStatsServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := client.QueryStats(ctx, &statsservice.QueryStatsRequest{Reset_: reset})
	if err != nil {
		return nil, err
	}

	tagTrafficMap := map[string]*xray.Traffic{}
	traffics := make([]*xray.Traffic, 0)
	for _, stat := range resp.GetStat() {
		matchs := trafficRegex.FindStringSubmatch(stat.Name)
		if len(matchs) < 4 {
			continue
		}
		isInbound := matchs[1] == "inbound"
		tag := matchs[2]
		isDown := matchs[3] == "downlink"
		if tag == "api" {
			continue
		}
		traffic, ok := tagTrafficMap[tag]
		if !ok {
			traffic = &xray.Traffic{IsInbound: isInbound, Tag: tag}
			tagTrafficMap[tag] = traffic
			traffics = append(traffics, traffic)
		}
		if isDown {
			traffic.Down = stat.Value
		} else {
			traffic.Up = stat.Value
		}
	}

	return traffics, nil
}

func EqualConfigBytes(a []byte, b []byte) bool {
	return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
}
