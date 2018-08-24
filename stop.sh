echo "Stopping logon server"
docker stop auth >/dev/null
docker rm auth >/dev/null
echo "Stopped logon server"