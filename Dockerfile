FROM golang:1.8

RUN go get github.com/go-redis/redis
RUN go get github.com/gocql/gocql
RUN go get github.com/ddliu/go-httpclient
RUN go get github.com/gorilla/mux
RUN go get golang.org/x/crypto/bcrypt

EXPOSE 6379 8080 9042 9142 9160

RUN mkdir -p /src/rofael.net/logon
WORKDIR /src/rofael.net/logon
COPY .\ .