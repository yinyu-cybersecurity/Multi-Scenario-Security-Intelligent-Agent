# CTF Pwn工具镜像
# 包含: pwntools, ROPgadget, pwndbg等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 替换为阿里云镜像源
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null || true

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb gdb-multiarch \
    libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

# Python Pwn工具
RUN pip install --no-cache-dir \
    pwntools \
    ROPgadget \
    capstone \
    keystone-engine \
    unicorn

# pwndbg (可选，构建时间较长)
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/pwndbg/pwndbg.git /opt/pwndbg && \
    cd /opt/pwndbg && ./setup.sh || true && \
    rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -r -s /bin/false ctfuser && \
    mkdir -p /workspace && chown -R ctfuser:ctfuser /workspace

# 工作目录
WORKDIR /workspace

# 切换到非root用户
USER ctfuser

CMD ["sleep", "infinity"]