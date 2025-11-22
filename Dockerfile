# -------- Build-Stage --------
FROM golang:1.25.4 AS builder

WORKDIR /app

# (optional, wenn du die ENV wirklich brauchst)
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
ENV GOPROXY="https://proxy.golang.org,direct"
ENV GOTOOLCHAIN="auto"

# Module cachen
COPY go.mod go.sum ./
RUN go mod download

# Restlicher Code
COPY . .

# Passe ./cmd/server an dein wirkliches main-Package an
# z.B. ./cmd/api, ./cmd/service oder einfach ./ wenn du nur ein Binary hast
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .

# -------- Runtime-Stage --------
FROM alpine:3.20

WORKDIR /app

# Für HTTPS / TLS etc.
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/app .

EXPOSE 8443

CMD ["./app"]
