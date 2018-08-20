echo "Stopping logon server"
docker stop signin >/dev/null
docker rm signin >/dev/null
echo "Stopped logon server"