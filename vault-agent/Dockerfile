FROM golang:1.21 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o vault-agent .

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/vault-agent .

# Create directories for config and data
RUN mkdir -p /app/config /app/data

EXPOSE 8080

CMD ["./vault-agent"]