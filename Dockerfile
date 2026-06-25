FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    make \
    git \
    check \
    pkg-config \
    netcat-openbsd \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["bash"]
