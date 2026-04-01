# CTF AD域工具镜像
# 包含: crackmapexec, impacket, bloodhound, certipy等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# 基础依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libkrb5-dev \
    libffi-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python工具
RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

RUN pipx install crackmapexec || true
RUN pipx install impacket || true
RUN pipx install bloodhound || true
RUN pipx install certipy-ad || true
RUN pipx install ldapdomaindump || true
RUN pipx install pywhisker || true

# 创建非root用户
RUN useradd -r -s /bin/false ctfuser && \
    mkdir -p /workspace && chown -R ctfuser:ctfuser /workspace

# 工作目录
WORKDIR /workspace

# 切换到非root用户
USER ctfuser

CMD ["sleep", "infinity"]