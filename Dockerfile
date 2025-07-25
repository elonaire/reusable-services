FROM rust:alpine

ARG DEBIAN_FRONTEND=noninteractive
ARG RUSTFLAGS='-C target-feature=-crt-static'

# Set the working directory to the service specified in the build argument
ARG SERVICE_NAME

ENV SERVICE_NAME=${SERVICE_NAME}

# Install necessary packages
RUN apk update && apk add --no-cache \
    perl    \
    musl-dev \
    openssl-dev \
    protobuf-dev


RUN rustup default stable

WORKDIR /app

# Copy the entire workspace
COPY . .
# Create the output directory for grpc
RUN mkdir lib/src/integration/grpc/out

# Build for release
RUN cargo build --release --package ${SERVICE_NAME}

# Final stage: use a lightweight image
FROM alpine:latest

ARG DEBIAN_FRONTEND=noninteractive
ARG SERVICE_NAME
ARG PORT
ARG GRPC_PORT

ENV SERVICE_NAME=${SERVICE_NAME}
ENV PORT=${PORT}
ENV GRPC_PORT=${GRPC_PORT}

# Copy necessary shared libraries
RUN apk add --no-cache \
    libgcc \
    musl \
    openssl \
    && rm -rf /var/cache/apk/*

# Create a non-root user
RUN adduser -D myuser
# Switch to the new user
USER myuser

# Copy the binary from the builder stage
COPY --from=0 /app/target/release/${SERVICE_NAME} .

# Expose the ports
EXPOSE ${PORT}
EXPOSE ${GRPC_PORT}

# Command to run
CMD ./${SERVICE_NAME}
