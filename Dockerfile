FROM golang:1.27-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go *.html ./
# go.mod and go.sum are the source of truth: the build fails rather than resolve anything new.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags="-s -w" -o cloudfiles .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /build/cloudfiles .
RUN mkdir -p /data/files
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://localhost:8080/up || exit 1
CMD ["./cloudfiles"]
