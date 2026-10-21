package router

import (
	"NanoKVM-Server/authn"
	"NanoKVM-Server/hardened"
	"NanoKVM-Server/middleware"
	"NanoKVM-Server/service/application"

	"github.com/gin-gonic/gin"
)

func applicationRouter(r *gin.Engine) {
	service := application.NewService()
	api := r.Group("/api").Use(middleware.CheckToken(), middleware.RequirePermission(authn.PermUpdate))

	api.GET("/application/version", service.GetVersion)            // get application version
	api.POST("/application/update/offline", service.OfflineUpdate) // update application offline

	// The hardened build installs only signed packages uploaded by hand: it
	// never fetches a manifest or a package from an update server.
	if hardened.Enabled {
		return
	}

	api.POST("/application/update", service.Update) // update application

	api.GET("/application/preview", service.GetPreview)  // get preview updates state
	api.POST("/application/preview", service.SetPreview) // set preview updates state

	api.GET("/application/update-server", service.GetUpdateServer)  // get custom update server
	api.POST("/application/update-server", service.SetUpdateServer) // set custom update server
}
