FROM golang:1.21-alpine AS builder
RUN mkdir /tmp/build
ADD . /tmp/build
WORKDIR /tmp/build
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/godns .

FROM scratch
COPY --from=builder /tmp/godns /godns
ENTRYPOINT ["/godns"]
