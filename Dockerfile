# Build the manager binary
FROM registry.access.redhat.com/ubi9/go-toolset:1.25.9-1778675823 as builder

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

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8-1782797275

WORKDIR /
COPY --from=builder /workspace/mocktitlements .
USER 65532:65532

ENTRYPOINT ["/mocktitlements"]
