# CTF 基础镜像 - 最小化
# 仅包含Python和基础工具，供其他镜像继承

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 阿里云镜像源
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null || true

# 最小化安装
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git unzip \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# pip配置阿里云镜像
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/

WORKDIR /workspace