package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/ddliu/go-httpclient"
	"github.com/go-redis/redis"
	"github.com/gocql/gocql"
	"github.com/gorilla/mux"

	"golang.org/x/crypto/bcrypt"
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

type SessionResponse struct {
	Code      int    `json:"code"`
	SessionID string `json:"session,omitempty"`
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

	// Connect to Redis
	cache := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	_, err := cache.Ping().Result()
	if err != nil {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

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

	// Check if user in cache, then check DB
	acct := StoredAccount{}
	val, err := cache.Get(request.User).Result()
	if val != "" {
		err = json.Unmarshal([]byte(val), &acct)
	} else if err := acctSess.Query(`SELECT userid, username, hash FROM users WHERE username = ? ALLOW FILTERING`, request.User).Consistency(gocql.One).Scan(&acct.UUID, &acct.User, &acct.Hash); err != nil {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		if err != gocql.ErrNotFound {
			log.Print(err)
		}
		return
	}

	// Add back to cache
	err = cache.Set(request.User, request, 0).Err()

	// Compare stored hash with password
	compare := bcrypt.CompareHashAndPassword([]byte(acct.Hash), []byte(request.Pass))
	if compare != nil {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

	// Check if sessionID already exists
	res, err := httpclient.Get("http://127.0.0.1:8081/api/v1/private/sessions/get/" + acct.UUID.String())
	sessionResponseBytes, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	sessionResp := SessionResponse{}
	err = json.Unmarshal(sessionResponseBytes, &sessionResp)
	if sessionResp.Code == 100 {
		resp.SessionKey = sessionResp.SessionID
	} else {
		// Generate new sessionID
		res, err = httpclient.Post("http://127.0.0.1:8081/api/v1/private/sessions/add/"+acct.UUID.String(), map[string]string{})
		sessionResponseBytes, err = ioutil.ReadAll(res.Body)
		res.Body.Close()
		err = json.Unmarshal(sessionResponseBytes, &sessionResp)
		if sessionResp.Code == 200 {
			resp.SessionKey = sessionResp.SessionID
		} else {
			resp.Code = SignInFail
			response, _ := json.Marshal(resp)
			fmt.Fprint(w, string(response))
			return
		}
	}

	// Send successful login
	resp.Code = SignInSuccess
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

	// Connect to Redis
	cache := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	_, err := cache.Ping().Result()
	if err != nil {
		resp.Code = SignInFail
		response, _ := json.Marshal(resp)
		fmt.Fprint(w, string(response))
		return
	}

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
	val, _ := cache.Get(request.User).Result()
	if err := acctSess.Query(`SELECT count(*) FROM users WHERE username = ? ALLOW FILTERING`,
		request.User); err != nil || count > 0 || val != "" {
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

	// Insert into cache
	err = cache.Set(acct.User, acct, 0).Err()

	resp.Code = SignUpSuccess
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))

	acctSess.Close()
}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/", DefaultEndpoint)
	r.HandleFunc("/api/v1/private/signin", SigninEndpoint).Methods("POST")
	r.HandleFunc("/api/v1/private/signup", SignupEndpoint).Methods("POST")

	httpclient.Defaults(httpclient.Map{
		httpclient.OPT_USERAGENT: "ChatService Auth Server",
		"Accept-Language":        "en-us",
	})

	if os.Getenv("PORT") == "" {
		os.Setenv("PORT", "8080")
	}

	if err := http.ListenAndServe(":"+os.Getenv("PORT"), r); err != nil {
		log.Fatal(err)
	}
}
