package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
)

// Result codes of operations
const (
	SignInSuccess  = 100
	SignInFail     = 101
	SignUpSuccess  = 200
	SignUpFail     = 201
	BodyReadFail   = 300
	BodyDecodeFail = 301
)

// RequestContent Describes the contents of a login/signup request
type RequestContent struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Response sent back to the user
type Response struct {
	Code       int    `json:"code"`
	SessionKey string `json:"session,omitempty"`
}

// StoredAccount Internal structure for stored account
type StoredAccount struct {
	User string
	Hash string
}

var sessions map[string]time.Time
var users map[string]StoredAccount

// RandomString Generates a random string of [A-Za-z0-9] of length n
func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

// DefaultEndpoint ...
func DefaultEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Default")
}

// SigninEndpoint ...
func SigninEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	resp := Response{}

	// Read contents of POST
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyReadFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	// Unmarshal contents into struct
	request := RequestContent{}
	if err = json.Unmarshal(body, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyDecodeFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	// Check if user exists
	acct, exists := users[request.User]
	if !exists {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	// Compare stored hash with password
	compare := bcrypt.CompareHashAndPassword([]byte(acct.Hash), []byte(request.Pass))
	if compare != nil {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	// Generate new session
	sessionID := RandomString(16)
	sessions[sessionID] = time.Now()

	// Send successful login
	resp.Code = SignInSuccess
	resp.SessionKey = sessionID
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}

// SignupEndpoint ...
func SignupEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	resp := Response{}

	// Read contents of POST
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyReadFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	// Unmarshal intp struct
	request := RequestContent{}
	if err = json.Unmarshal(body, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyDecodeFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	// Check if either user or password are blank
	if request.User == "" || request.Pass == "" {
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	// Check if user already exists
	if _, exists := users[request.User]; exists {
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	// Create new account
	acct := StoredAccount{}
	acct.User = request.User
	hash, err := bcrypt.GenerateFromPassword([]byte(request.Pass), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	// Success
	acct.Hash = string(hash)
	users[acct.User] = acct
	resp.Code = SignUpSuccess
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}

func main() {
	users = make(map[string]StoredAccount)
	sessions = make(map[string]time.Time)

	r := mux.NewRouter()
	r.HandleFunc("/", DefaultEndpoint)
	r.HandleFunc("/api/v1/private/signin", SigninEndpoint).Methods("POST")
	r.HandleFunc("/api/v1/private/signup", SignupEndpoint).Methods("POST")

	if os.Getenv("PORT") == "" {
		os.Setenv("PORT", "8080")
	}

	if err := http.ListenAndServe(":"+os.Getenv("PORT"), r); err != nil {
		log.Fatal(err)
	}
}
