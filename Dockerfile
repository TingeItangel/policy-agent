FROM golang:1.21 as builder

WORKDIR /app
COPY main.go .
RUN go mod init policy-agent && go mod tidy
RUN go get github.com/redis/go-redis/v9
RUN go get github.com/google/uuid
RUN go get k8s.io/client-go@latest
RUN go get k8s.io/api@latest

RUN go build -o agent

FROM gcr.io/distroless/base-debian10
WORKDIR /app
COPY --from=builder /app/agent .
COPY cert.pem .
COPY key.pem .
ENTRYPOINT ["/app/agent"]
