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

// TODO: Move all session stuff to the frontend service

// DefaultEndpoint ...
func DefaultEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Default")
}

// SigninEndpoint ...
func SigninEndpoint(w http.ResponseWriter, r *http.Request) {
	SetHeaders(w)
	resp := Response{}

	// Connect to Cassandra cluster and get session
	dbSession, err := ConnectToCassandra("accounts")
	if err != nil {
		log.Print("Cassandra connection failed")
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignInFail)
		return
	}
	defer dbSession.Close()

	// Connect to Redis
	cache, err := ConnectToRedis(0)
	if err != nil {
		log.Print("Redis connection failed")
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignInFail)
		return
	}

	// Read contents of POST
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		ResponseNoData(w, BodyReadFail)
		log.Print("Failed to read request")
		log.Print(err)
		return
	}

	// Unmarshal contents into struct
	request := RequestContent{}
	if err = json.Unmarshal(body, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		ResponseNoData(w, BodyDecodeFail)
		log.Print("Failed to unmarshal request")
		log.Print(err)
		return
	}

	// Check if user in cache, then check DB
	acct := StoredAccount{}
	cachedBytes, err := cache.Get(request.User).Result()
	retrievedFromCache := false
	if cachedBytes != "" {
		err = json.Unmarshal([]byte(cachedBytes), &acct)
		retrievedFromCache = true
	} else if err := dbSession.Query(`SELECT userid, username, hash FROM users WHERE username = ? ALLOW FILTERING`, request.User).Scan(&acct.UUID, &acct.User, &acct.Hash); err != nil {
		ResponseNoData(w, SignInFail)
		if err != gocql.ErrNotFound {
			w.WriteHeader(http.StatusInternalServerError)
			log.Print("Cassandra query failed")
			log.Print(err)
		}
		return
	}

	// Add back to cache
	if !retrievedFromCache {
		userBytes, err := json.Marshal(acct)
		err = cache.Set(acct.User, userBytes, 0).Err()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			ResponseNoData(w, SignInFail)
			log.Print("Redis caching failed")
			log.Print(err)
			return
		}
	}

	// Compare stored hash with password
	compare := bcrypt.CompareHashAndPassword([]byte(acct.Hash), []byte(request.Pass))
	if compare != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignInFail)
		log.Print("Bcrypt error")
		log.Print(compare)
		return
	}

	// TODO: Move to frontend
	// Check if sessionID already exists
	// sessionRequestBody := make(map[string]string)
	// sessionRequestBody["uuid"] = acct.UUID.String()
	// sessionRequestBody["origin"] = r.Header.Get("User-Agent")

	// Should try to change to GET
	// res, err := httpclient.PostJson("http://ilb/sessions/exists", sessionRequestBody)
	// sessionResponseBytes, err := ioutil.ReadAll(res.Body)
	// if err != nil {

	// }

	// res.Body.Close()
	// sessionResp := SessionResponse{}
	// err = json.Unmarshal(sessionResponseBytes, &sessionResp)
	// if err != nil {

	// }

	// if sessionResp.Code == 100 {
	// 	resp.SessionKey = sessionResp.SessionID
	// } else {
	// Generate new sessionID
	// 	res, err = httpclient.PostJson("http://ilb/sessions/add", sessionRequestBody)
	// 	if err != nil {
	// 		ResponseNoData(w, SignInFail)
	// 		w.WriteHeader(http.StatusInternalServerError)
	// 		log.Print("HTTP request error")
	// 		log.Print(err)
	// 		return
	// 	}

	// 	sessionResponseBytes, err = ioutil.ReadAll(res.Body)
	// 	if err != nil {
	// 		ResponseNoData(w, SignInFail)
	// 		w.WriteHeader(http.StatusInternalServerError)
	// 		log.Print("HTTP response read error")
	// 		log.Print(err)
	// 		return
	// 	}

	// 	res.Body.Close()
	// 	err = json.Unmarshal(sessionResponseBytes, &sessionResp)
	// 	if err != nil {
	// 		w.WriteHeader(http.StatusInternalServerError)
	// 		ResponseNoData(w, SignInFail)
	// 		log.Print("HTTP response unmarshal error")
	// 		log.Print(err)
	// 		return
	// 	}

	// 	if sessionResp.Code == 200 {
	// 		resp.SessionKey = sessionResp.SessionID
	// 	} else {
	// 		ResponseNoData(w, SignInFail)
	// 		return
	// 	}
	// }

	// Send successful login
	resp.Code = SignInSuccess
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}

// SignupEndpoint ...
func SignupEndpoint(w http.ResponseWriter, r *http.Request) {
	SetHeaders(w)
	resp := Response{}

	// Connect to Cassandra cluster and get session
	dbSession, err := ConnectToCassandra("accounts")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignInFail)
		log.Print("Cassandra connection error")
		log.Print(err)
		return
	}
	defer dbSession.Close()

	// Connect to Redis
	cache, err := ConnectToRedis(0)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignInFail)
		log.Print("Redis connection error")
		log.Print(err)
		return
	}

	// Read contents of POST
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		ResponseNoData(w, BodyReadFail)
		log.Print("Failed to read request")
		log.Print(err)
		return
	}

	// Unmarshal into struct
	request := RequestContent{}
	if err = json.Unmarshal(body, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		ResponseNoData(w, BodyDecodeFail)
		log.Print("Failed to unmarshal request")
		log.Print(err)
		return
	}

	// Check if either user or password are blank
	if request.User == "" || request.Pass == "" {
		ResponseNoData(w, SignUpFail)
		return
	}

	// Check if user already exists
	var count int
	val, err := cache.Get(request.User).Result()
	if err != nil && err != redis.Nil {
		log.Print("Redis query failed")
		log.Print(err)
	}
	if err := dbSession.Query(`SELECT count(*) FROM users WHERE username = ? ALLOW FILTERING`,
		request.User).Scan(&count); err != nil || count > 0 || val != "" {
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignUpFail)
		log.Print("Cassandra query failed")
		log.Print(err)
		return
	}

	// Create new account
	acct := StoredAccount{}
	acct.User = request.User
	hash, err := bcrypt.GenerateFromPassword([]byte(request.Pass), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignUpFail)
		log.Print(err)
		return
	}

	// Insert into database
	acct.Hash = string(hash)
	uid, _ := gocql.RandomUUID()
	if err := dbSession.Query(`INSERT INTO users (userid, username, hash) VALUES (?, ?, ?)`,
		uid, acct.User, acct.Hash).Exec(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		ResponseNoData(w, SignUpFail)
		log.Print(err)
		return
	}

	// Insert into cache
	err = cache.Set(acct.User, acct, 0).Err()

	resp.Code = SignUpSuccess
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}

// SignoutEndpoint DEPRECATED
func SignoutEndpoint(w http.ResponseWriter, r *http.Request) {
	// SetHeaders(w)
	// resp := Response{}

	// Connect to Cassandra cluster and get session
	// dbSession, err := ConnectToCassandra("accounts")
	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	ResponseNoData(w, SignInFail)
	// 	log.Print(err)
	// 	return
	// }
	// defer dbSession.Close()

	// Connect to Redis
	// cache, err := ConnectToRedis(0)
	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	ResponseNoData(w, SignInFail)
	// 	log.Print(err)
	// 	return
	// }

	// Read contents of POST
	// body, err := ioutil.ReadAll(r.Body)
	// if err != nil {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	ResponseNoData(w, BodyReadFail)
	// 	log.Print(err)
	// 	return
	// }

	// Unmarshal into struct
	// request := SignOutRequest{}
	// if err = json.Unmarshal(body, &request); err != nil {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	ResponseNoData(w, BodyDecodeFail)
	// 	log.Print(err)
	// 	return
	// }

	// Get account from username
	// acct := StoredAccount{}
	// val, err := cache.Get(request.User).Result()
	// if val != "" {
	// 	err = json.Unmarshal([]byte(val), &acct)
	// } else if err := dbSession.Query(`SELECT userid, username, hash FROM users WHERE username = ? ALLOW FILTERING`, request.User).Scan(&acct.UUID, &acct.User, &acct.Hash); err != nil {
	// 	ResponseNoData(w, SignInFail)
	// 	if err != gocql.ErrNotFound {
	// 		w.WriteHeader(http.StatusInternalServerError)
	// 		log.Print(err)
	// 	}
	// 	return
	// }

	// TODO: Move to frontend
	// Send session deactivation request
	// deactiveRequestBody := make(map[string]string)
	// deactiveRequestBody["uuid"] = acct.UUID.String()
	// deactiveRequestBody["origin"] = request.Origin
	// deactiveRequestBody["session"] = request.SessionID

	// res, err := httpclient.PostJson("http://ilb/sessions/remove", deactiveRequestBody)
	// resBytes, err := ioutil.ReadAll(res.Body)
	// res.Body.Close()
	// sessResp := SessionResponse{}
	// err = json.Unmarshal(resBytes, &sessResp)
	// if sessResp.Code == 301 || err != nil {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	ResponseNoData(w, BodyDecodeFail)
	// 	log.Print(err)
	// 	return
	// }

	// Send Response
	// resp.Code = SignUpSuccess
	// response, _ := json.Marshal(resp)
	// fmt.Fprint(w, string(response))
}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/", DefaultEndpoint)
	r.HandleFunc("/api/v1/private/auth/signin", SigninEndpoint).Methods("POST")
	r.HandleFunc("/api/v1/private/auth/signup", SignupEndpoint).Methods("POST")
	// r.HandleFunc("/api/v1/private/auth/signout", SignoutEndpoint).Methods("POST")

	hostname, _ := os.Hostname()
	httpclient.Defaults(httpclient.Map{
		httpclient.OPT_USERAGENT: "ChatService Auth Server: " + hostname,
		"Accept-Language":        "en-us",
	})

	if os.Getenv("PORT") == "" {
		os.Setenv("PORT", "80")
	}

	if err := http.ListenAndServe(":"+os.Getenv("PORT"), r); err != nil {
		log.Fatal(err)
	}
}
