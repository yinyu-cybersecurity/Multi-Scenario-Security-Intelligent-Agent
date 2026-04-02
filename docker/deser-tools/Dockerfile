# CTF反序列化工具镜像
# 包含: ysoserial, marshalsec, JNDIExploit, phpggc

FROM openjdk:11-jdk-slim

ENV DEBIAN_FRONTEND=noninteractive

# 替换为阿里云镜像源
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    git maven python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Maven阿里云镜像配置
RUN mkdir -p /root/.m2 && \
    echo '<settings><mirrors><mirror><id>aliyun</id><mirrorOf>central</mirrorOf><name>Aliyun Maven</name><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

# 工作目录
WORKDIR /tools

# ysoserial
RUN wget -q -O /tools/ysoserial.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar || true

# JNDIExploit
RUN git clone --depth 1 https://github.com/welk1n/JNDI-Injection-Exploit.git /tools/JNDIExploit && \
    cd /tools/JNDIExploit && mvn clean package -DskipTests || true

# marshalsec
RUN git clone --depth 1 https://github.com/mbechler/marshalsec.git /tools/marshalsec && \
    cd /tools/marshalsec && mvn clean package -DskipTests || true

# phpggc
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /tools/phpggc

# 创建非root用户
RUN useradd -r -s /bin/false ctfuser && \
    mkdir -p /workspace && chown -R ctfuser:ctfuser /workspace /tools

WORKDIR /workspace

# 切换到非root用户
USER ctfuser

CMD ["sleep", "infinity"]