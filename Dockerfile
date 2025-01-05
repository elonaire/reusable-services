FROM rust:1.83-alpine3.20

ARG DEBIAN_FRONTEND=noninteractive
ARG RUSTFLAGS='-C target-feature=-crt-static'

# Set the working directory to the service specified in the build argument
ARG SERVICE_NAME

ENV SERVICE_NAME=${SERVICE_NAME}

# Install necessary packages
RUN apk update && apk add --no-cache \
    perl    \
    musl-dev \
    openssl-dev

RUN rustup default nightly-2024-08-08

WORKDIR /app

# Copy the entire workspace
COPY . .

# Build for release
RUN cargo build --release --package ${SERVICE_NAME}

# Final stage: use a lightweight image
FROM alpine:latest
ARG DEBIAN_FRONTEND=noninteractive
ARG SERVICE_NAME
ARG PORT

ENV SERVICE_NAME=${SERVICE_NAME}
ENV PORT=${PORT}

# Copy necessary shared libraries
RUN apk add --no-cache \
    libgcc \
    musl \
    openssl \
    && rm -rf /var/cache/apk/*

# Copy the binary from the builder stage
COPY --from=0 /app/target/release/${SERVICE_NAME} .

# Expose the port
EXPOSE ${PORT}

# Command to run
CMD ./${SERVICE_NAME}
