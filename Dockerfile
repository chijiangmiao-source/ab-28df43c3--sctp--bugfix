# 星载控制中继 · SCTP 弱链路审计台
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY sctp ./sctp
COPY audit ./audit
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -buildvcs=false -o /out/server ./cmd/server

FROM alpine:3.20
RUN adduser -D app && mkdir -p /data && chown app:app /data
USER app
COPY --from=build /out/server /server
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["/server"]
