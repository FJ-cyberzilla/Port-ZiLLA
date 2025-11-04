FROM rust:1.70 as builder

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 portzilla

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/portzilla /usr/local/bin/portzilla

# Copy configuration
COPY config/default.toml /app/config/default.toml

# Create necessary directories
RUN mkdir -p /app/exports /app/logs /app/data && \
    chown -R portzilla:portzilla /app

USER portzilla

# Expose API port (if enabled)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD portzilla health-check || exit 1

# Default command
CMD ["portzilla", "interactive"]
