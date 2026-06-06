# Build the manager binary.
# Pin the builder to the runner's native arch ($BUILDPLATFORM) and let Go
# cross-compile to $TARGETARCH — avoids QEMU emulation on multi-arch builds.
FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
