FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    linux-tools-generic \
    make \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN ln -s "$(find /usr/lib/linux-tools -name bpftool | head -n 1)" /usr/local/bin/bpftool \
    && /usr/local/bin/bpftool version

WORKDIR /opt/academiq

COPY requirements-dashboard.txt requirements-test.txt ./
RUN pip3 install --break-system-packages -r requirements-test.txt

COPY . /opt/academiq/

CMD ["./deployments/linux-validation/run-benchmarks.sh"]
