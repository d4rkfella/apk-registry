FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN mkdir -p /out && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/apk-registry ./cmd/server

FROM alpine:3.24
RUN apk add --no-cache ca-certificates su-exec
RUN addgroup -S -g 10001 registry && adduser -S -D -H -u 10001 -G registry registry
COPY --from=build /out/apk-registry /usr/local/bin/apk-registry
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN mkdir -p /var/lib/apk-registry && chown registry:registry /var/lib/apk-registry
RUN chmod 0755 /usr/local/bin/docker-entrypoint
EXPOSE 8080 9094
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
