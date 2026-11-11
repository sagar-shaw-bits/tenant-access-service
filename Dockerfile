FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api ./cmd/api

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /out/api /app/api
COPY .env.example /app/.env.example
EXPOSE 8080
ENTRYPOINT ["/app/api"]
