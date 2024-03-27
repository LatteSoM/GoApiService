package main

import (
	"MarloService/database"
	_ "MarloService/docs"
	"MarloService/handlers"
	"MarloService/initializers"
	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"github.com/tbaehler/gin-keycloak/pkg/ginkeycloak"
)

func init() {
	initializers.EnvInitializer()
	//initializers.KeyCloackInitializer()
}

// @title MarloService API
// @version 1.0
// @description This is a sample MarloService API.
// @host localhost:8081
// @BasePath /
// @securityDefinitions.apiKey Bearer
// @in header
// @name Authorization
// @description "Bearer" токен от keycloak в header "Authorization". При вставке из flow, дописывать слово - Bearer

func main() {

	database.Init()
	initializers.EnvInitializer()
	//initializers.KeyCloackInitializer()

	router := gin.Default()
	router.Use(ginkeycloak.RequestLogger([]string{"uid"}, "data"))
	router.Use(gin.Recovery())
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	router.GET("/get_auth", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.Arr)

	// User routes
	router.GET("/search", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.Search)
	router.GET("/user_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllUsers)
	router.POST("/user", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreateUser)
	router.GET("/user/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadUserByID)
	router.PUT("/user/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdateUser)
	router.DELETE("/user/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeleteUser)

	// Practice routes
	router.GET("/practice_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllPractices)
	router.POST("/practice", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreatePractice)
	router.GET("/practice/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadPracticeByID)
	router.PUT("/practice/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdatePractice)
	router.DELETE("/practice/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeletePractice)

	// GroupMPT routes
	router.GET("/groupmpt_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllGroupMPT)
	router.POST("/groupmpt", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreateGroupMPT)
	router.GET("/groupmpt/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadGroupMPTByID)
	router.PUT("/groupmpt/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdateGroupMPT)
	router.DELETE("/groupmpt/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeleteGroupMPT)

	// GroupMarlo routes
	router.GET("/groupmarlo_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllGroupMarlo)
	router.POST("/groupmarlo", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreateGroupMarlo)
	router.GET("/groupmarlo/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadGroupMarloByID)
	router.PUT("/groupmarlo/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdateGroupMarlo)
	router.DELETE("/groupmarlo/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeleteGroupMarlo)

	// Маршруты для таблицы PracticeDays
	router.GET("/practiceday_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllPracticeDays)
	router.POST("/practiceday", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreatePracticeDay)
	router.GET("/practiceday/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadPracticeDayByID)
	router.PUT("/practiceday/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdatePracticeDay)
	router.DELETE("/practiceday/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeletePracticeDay)

	// Маршруты для таблицы PracticeShedule
	router.GET("/practiceschedule_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllShedule)
	router.POST("/practiceschedule", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreatePracticeShedule)
	router.GET("/practiceschedule/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadPracticeSheduleByID)
	router.PUT("/practiceschedule/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdatePracticeShedule)
	router.DELETE("/practiceschedule/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeletePracticeShedule)

	// Маршруты для таблицы PracticeConfig
	router.GET("/practiceconfig_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllPracticeConfigs)
	router.POST("/practiceconfig", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreatePracticeConfig)
	router.GET("/practiceconfig/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadPracticeConfigByID)
	router.PUT("/practiceconfig/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdatePracticeConfig)
	router.DELETE("/practiceconfig/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeletePracticeConfig)

	// Маршруты для таблицы Logs
	router.GET("/logs_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllLogs)
	router.POST("/logs", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreateLogEntry)
	router.GET("/logs/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadLogEntryByID)
	router.PUT("/logs/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdateLogEntry)
	router.DELETE("/logs/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeleteLogEntry)

	// Маршруты для таблицы Status
	router.GET("/status_all", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.GetAllStatus)
	router.POST("/status", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.CreateStatus)
	router.GET("/status/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.ReadStatusByID)
	router.PUT("/status/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.UpdateStatus)
	router.DELETE("/status/:id", handlers.TokenAuthMiddleware([]string{"emolie_role", "student", "administrator"}), handlers.DeleteStatus)

	router.Run(":8081")
}
