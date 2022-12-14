package main

import (
	"github.com/gin-gonic/gin"
	"go-jwt/controllers"
	"go-jwt/initializers"
	"go-jwt/middleware"
)

func init() {
	initializers.LoadEnvVariable()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}
func main() {
	r := gin.Default()
	r.POST("signup", controllers.SignUp)
	r.POST("login", controllers.Login)
	r.GET("validate", middleware.RequireMiddleware, controllers.Validate)
	r.Run()
}
