FROM golang:1.8

RUN go get github.com/go-redis/redis
RUN go get github.com/gocql/gocql
RUN go get github.com/ddliu/go-httpclient
RUN go get github.com/gorilla/mux
RUN go get golang.org/x/crypto/bcrypt

EXPOSE 8080

RUN mkdir -p /src/rofael.net/logon
WORKDIR /src/rofael.net/logon
COPY .\ .