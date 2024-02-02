package routes

import (
	"github.com/gorilla/mux"
)

func SetupRouter() *mux.Router {
	router := mux.NewRouter()

	SetupDocumentRoutes(router)
	SetupAuthRoutes(router)
	SetupCollaborationRoutes(router)

	return router
}
