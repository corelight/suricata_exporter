FROM golang:1.16-alpine AS builder

ENV CGO_ENABLED=0

WORKDIR /app/
COPY go.mod go.sum ./
RUN go mod download

ARG VERSION
COPY *.go ./
COPY testdata/*json ./testdata/
RUN go vet
RUN go test
RUN go build -ldflags "-X main.version=${VERSION}"


FROM gcr.io/distroless/static-debian11
COPY --from=builder /app/suricata_exporter .
EXPOSE 9917
ENTRYPOINT ["/suricata_exporter"]
