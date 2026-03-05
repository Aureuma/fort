FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/fortd ./cmd/fortd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/fort ./cmd/fort
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/fort-agent ./cmd/fort-agent

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/fortd /usr/local/bin/fortd
COPY --from=build /out/fort /usr/local/bin/fort
COPY --from=build /out/fort-agent /usr/local/bin/fort-agent

ENV FORT_ADDR=:8088 \
    FORT_STATE_PATH=/var/lib/fort/state.json \
    FORT_TOKEN_TTL=15m \
    FORT_REFRESH_SESSION_TTL=24h \
    FORT_RUN_TTL=60s \
    FORT_SECRET_TTL=120s

VOLUME ["/var/lib/fort"]
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/fortd"]
