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

func SetHeaders(w http.ResponseWriter) {
	// w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
}

func ConnectToCassandra(keyspace string) (*gocql.Session, error) {
	cluster := gocql.NewCluster("cass-master")
	cluster.Keyspace = keyspace
	cluster.Consistency = gocql.One
	session, err := cluster.CreateSession()
	return session, err
}

func ConnectToRedis(db int) (*redis.Client, error) {
	cache := redis.NewClient(&redis.Options{
		Addr:     "redis-master:6379",
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
