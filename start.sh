echo "Starting login server"
docker run -d -it -p 8080:8080 \
    --name=signin logon go run app.go utils.go
echo "Started login server"