FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

WORKDIR /app
COPY . ./
COPY cloud.pem ./
COPY ticket.html ./ticket.html
COPY ver ./ver

# Using go get.
RUN go get -d -v

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/jwtservice .

FROM scratch

# Copy our static executable.
COPY --from=builder /app/* /app/
ENTRYPOINT ["/app/jwtservice"]
