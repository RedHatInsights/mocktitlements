# Build the manager binary
FROM registry.access.redhat.com/hi/go:1.26.9-builder-1792443220@sha256:c62803d6a744c045f1087cefe8b2b046d09048bdc499dcf090eaa623f3b9452d as builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
USER 0
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GO111MODULE=on go build -ldflags="-w -s"

FROM registry.access.redhat.com/hi/static:1792647314@sha256:c51e17de4a96e3bd68361830ec54f3c43ffcf398b82765a1ce250bd4a0d99d1f

WORKDIR /
COPY --from=builder /workspace/mocktitlements .
USER 65532:65532

ENTRYPOINT ["/mocktitlements"]
