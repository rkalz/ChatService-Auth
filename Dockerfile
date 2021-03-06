FROM golang:1.11-alpine

RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh

RUN go get github.com/go-redis/redis
RUN go get github.com/gocql/gocql
RUN go get github.com/ddliu/go-httpclient
RUN go get github.com/gorilla/mux
RUN go get golang.org/x/crypto/bcrypt

EXPOSE 80 6379 9042 9142 9160

RUN mkdir -p /src/rofael.net/logon
WORKDIR /src/rofael.net/logon
COPY .\ .
