# ==============================================================================
# STAGE 1: Build the Go Application
# ==============================================================================
FROM golang:1.21-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Download necessary Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire Go source code
COPY . .

# Build the executable dynamically as an unprivileged static Linux AMD64 binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sme-server ./cmd/server/main.go

# ==============================================================================
# STAGE 2: Minimum Viable Runtime Container (< 25MB)
# ==============================================================================
FROM alpine:latest  

# Add required certificates for outbound HTTPS calls (e.g., to Resend API)
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy the statically compiled binary from the builder
COPY --from=builder /app/sme-server .

# Explicitly assign permissions to make the binary executable
RUN chmod +x ./sme-server

# Expose the default application port 
EXPOSE 8082

# Run the Go binary directly (no framework overhead)
CMD ["./sme-server"]
