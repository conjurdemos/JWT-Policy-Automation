## Building the container:

VER=$(cat ver)

container="jwtservice:$VER"

docker build -t $container .
