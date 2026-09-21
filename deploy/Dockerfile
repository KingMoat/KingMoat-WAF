# KingMoat all-in-one image: data plane + console in one process.
# Build:  docker build -f deploy/Dockerfile -t kingmoat:dev .
# Run:    see deploy/docker-compose.yml
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=dev" -o /out/kingmoat ./cmd/kingmoat \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=dev" -o /out/kingmoat-cli ./cmd/kingmoat-cli

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kingmoat /kingmoat
COPY --from=build /out/kingmoat-cli /kingmoat-cli
WORKDIR /data
VOLUME /data
# 8080/8443 = data plane (from config.json), 8081 = console (webui + api + metrics)
EXPOSE 8080 8443 8081
ENTRYPOINT ["/kingmoat"]
CMD ["-config", "/data/config.json", "-console-addr", ":8081", "-console-db", "/data/kingmoat.db"]
