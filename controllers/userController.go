package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go-jwt/initializers"
	"go-jwt/models"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"time"
)

func SignUp(context *gin.Context) {

	//get information from request body
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if context.BindJSON(&body) != nil {
		context.JSON(400, gin.H{
			"error": "fail to read body",
		})
		return
	}
	//hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		context.JSON(400, gin.H{
			"error": "fail to hash password",
		})
		return
	}

	user := models.User{
		Email:    body.Email,
		Username: body.Username,
		Password: string(hash),
	}
	result := initializers.DB.Create(&user)
	if result.Error != nil {
		context.JSON(400, gin.H{
			"message": "can't create user",
		})
		return
	}
	context.JSON(200, gin.H{
		"data": user,
	})

}
func Login(ctx *gin.Context) {
	var body struct {
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if ctx.BindJSON(&body) != nil {
		ctx.JSON(400, gin.H{
			"error": "fail to read body",
		})
		return
	}
	// checking request body user
	var user models.User
	initializers.DB.First(&user, "username=?", body.Username)
	if user.ID == 0 {
		ctx.JSON(400, gin.H{"error": "Invalid username "})
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		ctx.JSON(400, gin.H{"error": "Invalid password "})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		ctx.JSON(400, gin.H{"error": "false to create token"})
		return
	}

	// set cookie
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("Authorization", tokenString, 3600*30*24, "", "", false, true)
	// return value
	ctx.JSON(200, gin.H{
		//"token": tokenString,
	})
}

func Validate(ctx *gin.Context) {
	user, _ := ctx.Get("user")
	ctx.JSON(200, gin.H{
		"message": user,
	})
}
