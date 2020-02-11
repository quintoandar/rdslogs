FROM golang:1.13-alpine

WORKDIR /go/src/github.com/honeycombio/rdslogs
RUN apk update && apk add git
COPY . /go/src/github.com/honeycombio/rdslogs
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -a -tags netgo -ldflags '-w' -o /go/bin/rdslogs

FROM golang:1.9-alpine
COPY --from=0 /go/bin/rdslogs /rdslogs
EXPOSE 3000
ENTRYPOINT ["/rdslogs"]
