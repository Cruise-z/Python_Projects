# 基础：Maven 3.9.x + Eclipse Temurin JDK 11（可换成 17/21）
FROM maven:3.9.6-eclipse-temurin-11

# 工作区 & Maven 本地仓库缓存位置
ENV WORKDIR=/workspace \
    MAVEN_OPTS="-Dmaven.repo.local=/workspace/.m2" \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    DISPLAY=":99"

# 常用基础工具 + JavaFX/Swing 运行所需依赖 + GStreamer（javafx-media 用）
# Xvfb 提供虚拟显示；字体/音频库避免界面/媒体初始化失败
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata locales \
    curl wget git nano vim less tree unzip zip \
    xz-utils tar binutils \
    xvfb xauth x11-apps \
    libgtk-3-0 libasound2 fonts-dejavu \
    libxtst6 libxrender1 libxext6 libxi6 libxrandr2 libgl1 \
    gstreamer1.0-tools gstreamer1.0-libav \
    gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
    && rm -rf /var/lib/apt/lists/*

# 设定 UTF-8 本地化（对部分 UI/日志编码友好）
RUN sed -i 's/# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# 工作区与 Maven 缓存目录
RUN mkdir -p $WORKDIR $WORKDIR/.m2
WORKDIR $WORKDIR

# 启动时开启一个虚拟显示（:99），并保持容器驻留
# 如需把容器当命令行使用，可改成 ENTRYPOINT ["mvn"] / CMD ["-v"]
CMD ["bash", "-lc", "Xvfb :99 -screen 0 1280x800x24 & while sleep 3600; do :; done"]
