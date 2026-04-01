# CTF杂项工具镜像
# 包含: jwt_tool, ssrfmap, gopherus, githacker, binwalk等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk foremost exiftool \
    && rm -rf /var/lib/apt/lists/*

# Python工具
RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

# jwt_tool
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip install -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# SSRFmap
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/ssrfmap && \
    pip install -r /opt/ssrfmap/requirements.txt

# Gopherus
RUN git clone --depth 1 https://github.com/tarunkant/Gopherus.git /opt/gopherus && \
    cd /opt/gopherus && ./install.sh || true

# GitHacker
RUN pipx install githacker || true

# 创建非root用户
RUN useradd -r -s /bin/false ctfuser && \
    mkdir -p /workspace && chown -R ctfuser:ctfuser /workspace /opt

WORKDIR /workspace

# 切换到非root用户
USER ctfuser

CMD ["sleep", "infinity"]