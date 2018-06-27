package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-redis/redis"
	"github.com/gocql/gocql"
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

type SignOutRequest struct {
	Origin    string `json:"origin"`
	User      string `json:"username"`
	SessionID string `json:"session"`
}

func SetHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
}

func CassConnect(keyspace string) *gocql.Session {
	acctCluster := gocql.NewCluster("127.0.0.1")
	acctCluster.Keyspace = keyspace
	acctCluster.Consistency = gocql.Three
	acctSess, _ := acctCluster.CreateSession()
	return acctSess
}

func RedisConnect(db int) (*redis.Client, error) {
	cache := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       db,
	})
	_, err := cache.Ping().Result()
	return cache, err
}

func ResponseNoData(w http.ResponseWriter, code int) {
	resp := Response{}
	resp.Code = code
	response, _ := json.Marshal(resp)
	fmt.Fprint(w, string(response))
}
