FROM golang:1.24.5-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o worker ./cmd/cron

FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /app/worker .

USER nonroot:nonroot

ENTRYPOINT ["./worker"]
