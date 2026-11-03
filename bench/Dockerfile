FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libdpdk-dev git iproute2 ethtool nftables \
    python3 python3-scapy python3-matplotlib linux-perf strace util-linux procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
CMD ["sleep", "infinity"]
