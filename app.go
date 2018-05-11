package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"
)

const (
	SignInSuccess  = 100
	SignInFail     = 101
	SignUpSuccess  = 200
	SignUpFail     = 201
	BodyReadFail   = 300
	BodyDecodeFail = 301
)

type RequestContent struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type Response struct {
	Code       int    `json:"code"`
	SessionKey string `json:"session,omitempty"`
}

type StoredAccount struct {
	User string
	Hash string
	Salt string
}

var sessions map[string]time.Time
var users map[string]StoredAccount

func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func DefaultEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Default")
}

func SigninEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	resp := Response{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyReadFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	request := RequestContent{}
	if err = json.Unmarshal(body, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyDecodeFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	user, exists := users[request.User]
	if !exists {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	saltedPass := request.Pass + user.Salt
	hash := sha256.Sum256([]byte(saltedPass))
	hashString := hex.EncodeToString(hash[:])

	if hashString != user.Hash {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	session := RandomString(16)
	sessions[session] = time.Now()

	resp.Code = SignInSuccess
	resp.SessionKey = session
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}

func SignupEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	resp := Response{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyReadFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	request := RequestContent{}
	if err = json.Unmarshal(body, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Code = BodyDecodeFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	if request.User == "" || request.Pass == "" {
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	if _, exists := users[request.User]; exists {
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	user := StoredAccount{}
	user.User = request.User

	user.Salt = RandomString(12)
	saltedPass := request.Pass + user.Salt
	hash := sha256.Sum256([]byte(saltedPass))
	user.Hash = hex.EncodeToString(hash[:])

	users[user.User] = user
	resp.Code = SignUpSuccess
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}

func main() {
	users = make(map[string]StoredAccount)
	sessions = make(map[string]time.Time)

	r := mux.NewRouter()
	r.HandleFunc("/", DefaultEndpoint)
	r.HandleFunc("/api/v1/signin", SigninEndpoint).Methods("POST")
	r.HandleFunc("/api/v1/signup", SignupEndpoint).Methods("POST")

	if os.Getenv("PROD") == "" {
		if err := http.ListenAndServeTLS(":8443", "server.crt", "server.key", r); err != nil {
			log.Fatal(err)
		}
	} else {
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache("certs"),
		}

		server := &http.Server{
			Addr:    ":443",
			Handler: r,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}

		go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
		server.ListenAndServeTLS("", "")
	}
}
