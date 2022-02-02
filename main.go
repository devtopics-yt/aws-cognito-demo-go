package main

import (
	"cognito-demo/pkg/auth"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func main() {
	cognitoClient := auth.Init()

	r := chi.NewRouter()
	r.Use(middleware.Logger, middleware.WithValue("CognitoClient", cognitoClient))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	r.Post("/signup", signUp)

	r.Post("/signin", signIn)

	r.Get("/verify", verifyToken)

	port := os.Getenv("PORT")

	fmt.Println("starting server!")
	http.ListenAndServe(fmt.Sprintf(":%s", port), r)
}

type SignUpRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func signUp(w http.ResponseWriter, r *http.Request) {
	// parse the request body
	var req SignUpRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get client from context
	cognitoClient, ok := r.Context().Value("CognitoClient").(*auth.CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context", http.StatusInternalServerError)
		return
	}

	// build a signup request
	awsReq := &cip.SignUpInput{
		ClientId: aws.String(cognitoClient.AppClientId),
		Username: aws.String(req.Username),
		Password: aws.String(req.Password),
	}

	// make the signup request
	_, err = cognitoClient.SignUp(r.Context(), awsReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	confirmInput := &cip.AdminConfirmSignUpInput{
		UserPoolId: aws.String(cognitoClient.UserPoolId),
		Username:   aws.String(req.Username),
	}

	// auto confirm all users.
	_, err = cognitoClient.AdminConfirmSignUp(r.Context(), confirmInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("signup!"))
}

type SignInRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SignInResponse struct {
	// The access token.
	AccessToken *string `json:"access_token"`

	// The expiration period of the authentication result in seconds.
	ExpiresIn int32 `json:"expires_in"`

	// The ID token.
	IdToken *string `json:"id_token"`

	// The refresh token.
	RefreshToken *string `json:"refresh_token"`

	// The token type.
	TokenType *string `json:"token_type"`
}

func signIn(w http.ResponseWriter, r *http.Request) {
	// parse the request body
	var req SignInRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get client from context
	cognitoClient, ok := r.Context().Value("CognitoClient").(*auth.CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context", http.StatusInternalServerError)
		return
	}

	signInInput := &cip.AdminInitiateAuthInput{
		AuthFlow:       "ADMIN_USER_PASSWORD_AUTH",
		ClientId:       aws.String(cognitoClient.AppClientId),
		UserPoolId:     aws.String(cognitoClient.UserPoolId),
		AuthParameters: map[string]string{"USERNAME": req.Username, "PASSWORD": req.Password},
	}

	output, err := cognitoClient.AdminInitiateAuth(r.Context(), signInInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := &SignInResponse{
		AccessToken:  output.AuthenticationResult.AccessToken,
		ExpiresIn:    output.AuthenticationResult.ExpiresIn,
		IdToken:      output.AuthenticationResult.IdToken,
		RefreshToken: output.AuthenticationResult.RefreshToken,
		TokenType:    output.AuthenticationResult.TokenType,
	}
	_ = json.NewEncoder(w).Encode(res)
}

// GET -H "Authorization: Bearer eyXYZ"

func verifyToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	splitAuthHeader := strings.Split(authHeader, " ")
	if len(splitAuthHeader) != 2 {
		http.Error(w, "Missing or invalid authorization header", http.StatusBadRequest)
		return
	}

	// Get client from context
	cognitoClient, ok := r.Context().Value("CognitoClient").(*auth.CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context", http.StatusInternalServerError)
		return
	}

	pubKeyURL := "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"
	formattedURL := fmt.Sprintf(pubKeyURL, os.Getenv("AWS_DEFAULT_REGION"), cognitoClient.UserPoolId)

	keySet, err := jwk.Fetch(r.Context(), formattedURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := jwt.Parse(
		[]byte(splitAuthHeader[1]),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username, _ := token.Get("cognito:username")

	fmt.Printf("The username: %v\n", username)
	fmt.Println(token)

	// Success return 200
	return
}
