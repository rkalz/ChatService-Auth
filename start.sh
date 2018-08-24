echo "Starting login server"
docker run -d -it --name=auth auth go run app.go utils.go
echo "Started login server"