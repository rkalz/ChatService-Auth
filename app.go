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

	"github.com/gocql/gocql"

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
	UUID gocql.UUID
	User string
	Hash string
}

var sessions map[string]time.Time

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

	// Connect to Cassandra cluster and get session
	acctCluster := gocql.NewCluster("127.0.0.1", "127.0.0.2", "127.0.0.3")
	acctCluster.Keyspace = "accounts"
	acctCluster.Consistency = gocql.Three
	acctSess, _ := acctCluster.CreateSession()
	defer acctSess.Close()

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
	acct := StoredAccount{}
	if err := acctSess.Query(`SELECT userid, username, hash FROM users WHERE username = ? ALLOW FILTERING`, request.User).Consistency(gocql.One).Scan(&acct.UUID, &acct.User, &acct.Hash); err != nil {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		if err != gocql.ErrNotFound {
			log.Print(err)
		}
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

	// Connect to Cassandra cluster and get session
	acctCluster := gocql.NewCluster("127.0.0.1", "127.0.0.2", "127.0.0.3")
	acctCluster.Keyspace = "accounts"
	acctCluster.Consistency = gocql.Three
	acctSess, _ := acctCluster.CreateSession()
	defer acctSess.Close()

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

	// Unmarshal into struct
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
	var count int
	if err := acctSess.Query(`SELECT count(*) FROM users WHERE username = ? ALLOW FILTERING`, request.User); err != nil || count > 0 {
		w.WriteHeader(http.StatusInternalServerError)
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
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

	// Insert into database
	acct.Hash = string(hash)
	uid, _ := gocql.RandomUUID()
	if err := acctSess.Query(`INSERT INTO users (userid, username, hash) VALUES (?, ?, ?)`,
		uid, acct.User, acct.Hash).Exec(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		resp.Code = SignUpFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		log.Print(err)
		return
	}

	resp.Code = SignUpSuccess
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))

	acctSess.Close()
}

func main() {
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
