cd ..

docker build -t klnet.owner.oauth .

docker stop oauth

docker run -d -it --rm --name "oauth" --network server -p 5003:5002 -v /DATA/KLNET/OWNER:/OWNER klnet.owner.oauth

echo "build finish"

docker logs -f oauth
