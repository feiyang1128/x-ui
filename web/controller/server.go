package controller

import (
	"time"
	"x-ui/core"
	"x-ui/web/global"
	"x-ui/web/service"

	"github.com/gin-gonic/gin"
)

type ServerController struct {
	BaseController

	serverService service.ServerService

	lastStatus        *service.Status
	lastGetStatusTime time.Time

	lastVersionsByCore  map[string][]string
	lastGetVersionsTime map[string]time.Time
}

func NewServerController(g *gin.RouterGroup) *ServerController {
	a := &ServerController{
		lastGetStatusTime:  time.Now(),
		lastVersionsByCore: map[string][]string{},
		lastGetVersionsTime: map[string]time.Time{},
	}
	a.initRouter(g)
	a.startTask()
	return a
}

func (a *ServerController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/server")

	g.Use(a.checkLogin)
	g.POST("/status", a.status)
	g.POST("/getCoreVersion/:core", a.getCoreVersion)
	g.POST("/installCore/:core/:version", a.installCore)
}

func (a *ServerController) refreshStatus() {
	a.lastStatus = a.serverService.GetStatus(a.lastStatus)
}

func (a *ServerController) startTask() {
	webServer := global.GetWebServer()
	c := webServer.GetCron()
	c.AddFunc("@every 2s", func() {
		now := time.Now()
		if now.Sub(a.lastGetStatusTime) > time.Minute*3 {
			return
		}
		a.refreshStatus()
	})
}

func (a *ServerController) status(c *gin.Context) {
	a.lastGetStatusTime = time.Now()

	jsonObj(c, a.lastStatus, nil)
}

func (a *ServerController) getCoreVersion(c *gin.Context) {
	coreType := core.Type(c.Param("core"))
	coreKey := string(coreType)
	now := time.Now()
	if lastTime, ok := a.lastGetVersionsTime[coreKey]; ok && now.Sub(lastTime) <= time.Minute {
		jsonObj(c, a.lastVersionsByCore[coreKey], nil)
		return
	}

	versions, err := a.serverService.GetCoreVersions(coreType)
	if err != nil {
		jsonMsg(c, "获取版本", err)
		return
	}

	a.lastVersionsByCore[coreKey] = versions
	a.lastGetVersionsTime[coreKey] = time.Now()

	jsonObj(c, versions, nil)
}

func (a *ServerController) installCore(c *gin.Context) {
	coreType := core.Type(c.Param("core"))
	version := c.Param("version")
	err := a.serverService.UpdateCore(coreType, version)
	jsonMsg(c, "安装内核", err)
}
