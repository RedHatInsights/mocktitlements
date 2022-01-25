# Build the manager binary
FROM registry.access.redhat.com/ubi8/go-toolset:1.15.7 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
# COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
USER 0
RUN go mod download

COPY main.go main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/mocktitlements .
USER 65532:65532

ENTRYPOINT ["/mocktitlements"]
