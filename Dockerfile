FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    wget \
    pkg-config \
    libssl-dev \
    gnupg \
    lsb-release \
    libcurl4-openssl-dev \
    ca-certificates \
    libasio-dev \ 
    liblzma-dev \
    zlib1g-dev \
    libxml2-dev

# Install MongoDB C Driver
WORKDIR /tmp
RUN curl -LO https://github.com/mongodb/mongo-c-driver/releases/download/1.24.4/mongo-c-driver-1.24.4.tar.gz && \
    tar -xzf mongo-c-driver-1.24.4.tar.gz && \
    cd mongo-c-driver-1.24.4 && \
    mkdir -p build && \
    cd build && \
    cmake -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF .. && \
    make -j$(nproc) && make install && \
    ldconfig

# Install MongoDB C++ Driver
WORKDIR /tmp
RUN curl -LO https://github.com/mongodb/mongo-cxx-driver/releases/download/r3.8.0/mongo-cxx-driver-r3.8.0.tar.gz && \
    tar -xzf mongo-cxx-driver-r3.8.0.tar.gz && \
    cd mongo-cxx-driver-r3.8.0 && \
    mkdir -p build && \
    cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && make install && \
    ldconfig

# Set working directory for your project
WORKDIR /app

# Copy source files
COPY . .

# Create and enter build directory
RUN mkdir -p build
WORKDIR /app/build

# Compile the project
RUN cmake .. && make -j$(nproc)

# Expose the port
EXPOSE 18080

# Run the app
CMD ["./Pegra"]
