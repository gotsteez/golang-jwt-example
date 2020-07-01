package controller

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/unrolled/render"
)

// Credentials is the credentials the user would submit in a json request
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login is the login route to handle user authentication
// example of what is suppose to happen when you log into the application
func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	rend := render.New()

	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		log.Println("Error when decoding credentials in controller.go")
	}

	// just an example of some very strong username and password combinations
	if creds.Username == "admin" && creds.Password == "password123" {
		t, rt, err := generateTokenpair(creds)

		if err != nil {
			log.Println("Error while generating token pair")
			return
		}

		// For security purposes, the refresh token should be http-only
		// this prevents XSS and alike methods of cookie jacking. Only way
		// to jack the refresh_token now is through MITM attacks
		ck := http.Cookie{
			Name:     "refresh_token",
			Value:    rt,
			HttpOnly: true,
		}

		http.SetCookie(w, &ck)

		// Because the access_token expires quickly, it doesn't need to be an http cookie
		// and can be sent as a bearer authentication header
		rend.JSON(w, 200, map[string]string{
			"access_token": t,
		})
	}
}

// RefreshAccessToken takes refresh token from http-only cookie, so that it is secure
// Serves as an example of what to do when the access token expires
func RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("refresh_token")
	rend := render.New()

	if err != nil {
		log.Println("Error in RefreshAccessToken while getting refresh token", err)
		rend.JSON(w, 400, map[string]string{
			"error": "No refresh token found",
		})
		return
	}

	t, err := getNewAccessToken(token.Value)

	if err != nil {
		log.Println("Error while generating new access token", err)
		rend.JSON(w, 404, map[string]string{
			"error": err.Error(),
		})
		return
	}

	rend.JSON(w, 200, map[string]string{
		"access_token": t,
	})
}

// GetSecret allows users that are logged in to see what the secret is
// Serves as an example of fetching data with the jwt access token
func GetSecret(w http.ResponseWriter, r *http.Request) {
	type ReqBody struct {
		AccessToken string `json:"access_token"`
	}
	rend := render.New()

	var rb ReqBody
	err := json.NewDecoder(r.Body).Decode(&rb)

	if err != nil || rb.AccessToken == "" {
		rend.JSON(w, 400, map[string]string{
			"error": "Unable to find access token in the body",
		})
		return
	}

	// Autheneticate the authentication token. In a production level application,
	// this should be in a middleware so it can be reused. However, because this is
	// a barebones example, I just have it mixed in with the route

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(rb.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if err != nil {
		log.Println("Error while decoding jwt from body", err)
		rend.JSON(w, 400, map[string]string{
			"error": "Access token could not be parsed properly",
		})
		return
	}

	// check if the access token is expired
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		rend.JSON(w, 400, map[string]string{
			"error": "Access token is expired, please get a new one from /refresh",
		})
		return
	}

	log.Println("Token is getting secret: ", token)
	rend.JSON(w, 200, map[string]string{
		"secret": claims["secret_msg"].(string),
	})
}

// When a user logs in, generateTokenpair creates a access token and refresh token
// that can be used to access information
func generateTokenpair(creds Credentials) (t, rt string, err error) {
	// first generate a quickly expiring access token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims for access token
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = creds.Username
	claims["secret_msg"] = "Shhhhh!"
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	claims["sub"] = 1

	// Generate encoded token that is signed and contains claims from above
	t, err = token.SignedString([]byte("secret")) // in production, use os.Getend() for env variables

	if err != nil {
		return "", "", err
	}

	// generates a longer refresh token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["sub"] = 1 // sub is a unique user ID to identify the user. If you are using MongoDB, this can be _id
	rtClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	rt, err = refreshToken.SignedString([]byte("secret"))
	if err != nil {
		return "", "", err
	}

	return t, rt, nil
}

// getNewAccessToken gives you a new access token to use when the current one expires
func getNewAccessToken(rt string) (t string, err error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(rt, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if err != nil {
		log.Println(err)
		return "", err
	}

	// Check if the refresh token is expired
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		return "", errors.New("Token has expired, please log in")
	}

	// I don't do much here, but you should be making database calls to update the data of
	// your access token, such as statistics
	if claims["sub"].(float64) == 1 {
		newClaims := token.Claims.(jwt.MapClaims)
		newClaims["name"] = "admin"
		newClaims["secret msg"] = "Shhhhh!"
		newClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

		t, err = token.SignedString([]byte("secret"))
		return t, nil
	}

	return "", errors.New("Unidentified sub")
}
