FROM golang:1.21-alpine AS builder
RUN mkdir /tmp/build \
    && apk add --no-cache git
ADD . /tmp/build
WORKDIR /tmp/build
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/godns .

FROM scratch
ADD config.yml /config.yml
COPY --from=builder /tmp/godns /godns
ENTRYPOINT ["/godns", "--config", "/config.yml"]
