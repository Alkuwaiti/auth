FROM alpine
COPY ./bin/server /server

EXPOSE 8081
ENTRYPOINT ["/server"]

