# Stage 1: Build the manager binary
FROM golang:1.21 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy Go module files and download deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

# Build binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# Stage 2: Download Trivy
FROM alpine:3.18 AS trivy-downloader
RUN apk add --no-cache curl
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /trivy-bin

# Stage 3: Final runtime image
FROM ubuntu:22.04

# Add dependencies required by Trivy (ca-certificates, etc.)
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean

WORKDIR /

# Copy manager binary from builder
COPY --from=builder /workspace/manager /manager

# Copy Trivy binary
COPY --from=trivy-downloader /trivy-bin/trivy /usr/local/bin/trivy

# Run as non-root user
RUN useradd -u 10001 -r -s /usr/sbin/nologin manageruser
USER 10001

ENTRYPOINT ["/manager"]
