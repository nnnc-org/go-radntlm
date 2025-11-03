# Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker's build cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application
# CGO_ENABLED=0 ensures a static binary without external C dependencies
# -trimpath removes file paths for smaller binaries
# -ldflags="-s -w" strips debugging info and symbol table for smaller binaries
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o go-radntlm .

# Final Stage
FROM alpine:latest

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/go-radntlm .
# Copy templates directory
COPY --from=builder /app/internal/webui/templates ./internal/webui/templates

# Expose the port your application listens on (e.g., 8080)
EXPOSE 8080

# Command to run the application when the container starts
ENTRYPOINT [ "/app/go-radntlm" ]
