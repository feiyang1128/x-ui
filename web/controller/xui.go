package controller

import (
	"github.com/gin-gonic/gin"
	"x-ui/core"
	"x-ui/web/service"
)

type XUIController struct {
	BaseController

	xrayService service.XrayService

	inboundController *InboundController
	settingController *SettingController
}

func NewXUIController(g *gin.RouterGroup) *XUIController {
	a := &XUIController{}
	a.initRouter(g)
	return a
}

func (a *XUIController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/xui")
	g.Use(a.checkLogin)

	g.GET("/", a.index)
	g.GET("/inbounds", a.inbounds)
	g.GET("/setting", a.setting)

	a.inboundController = NewInboundController(g)
	a.settingController = NewSettingController(g)
}

func (a *XUIController) index(c *gin.Context) {
	html(c, "index.html", "Dashboard", nil)
}

func (a *XUIController) inbounds(c *gin.Context) {
	html(c, "inbounds.html", "Inbounds", a.getPageData())
}

func (a *XUIController) setting(c *gin.Context) {
	html(c, "setting.html", "Settings", a.getPageData())
}

func (a *XUIController) getPageData() gin.H {
	coreTypes := a.xrayService.GetInstalledCoreTypes()
	coreTypeStrings := make([]string, 0, len(coreTypes))
	for _, coreType := range coreTypes {
		coreTypeStrings = append(coreTypeStrings, string(coreType))
	}
	defaultCoreType := string(core.Xray)
	if len(coreTypes) > 0 {
		defaultCoreType = string(coreTypes[0])
	}
	return gin.H{
		"availableCoreTypes": coreTypeStrings,
		"defaultCoreType":    defaultCoreType,
	}
}
