FROM golang:1.8-alpine

COPY . .

WORKDIR ./server

RUN go build -o /bin/turtleauth

ENTRYPOINT ["turtleauth"]
