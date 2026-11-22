# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod .
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOTOOLCHAIN=local GOPROXY=off \
    go build -trimpath -ldflags="-s -w" -o /out/ex1b ./cmd/ex1b
RUN mkdir -p /runtime-root/data && chmod 0700 /runtime-root/data && touch /runtime-root/data/.volume

FROM scratch
COPY --from=build /out/ex1b /ex1b
COPY --from=build --chown=10001:10001 /runtime-root/ /
USER 10001:10001
EXPOSE 4443 4444 4445 4446 4447
ENTRYPOINT ["/ex1b", "web", "--listen", "0.0.0.0:4443", "--data", "/data"]
CMD ["--origin", "https://localhost:4443"]
