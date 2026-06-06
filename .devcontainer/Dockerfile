FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get -y install --no-install-recommends \
    build-essential gcc g++ make \
    autoconf automake libtool pkg-config \
    git \
    libgtk-4-dev libglib2.0-dev \
    libgnutls28-dev gnutls-bin \
    libsqlite3-dev libgcrypt20-dev libreadline-dev \
    libgdk-pixbuf2.0-dev \
    gettext intltool iso-codes \
    weston mutter \
    python3-gi gir1.2-atspi-2.0 at-spi2-core dbus-x11 \
    xserver-xorg-core xserver-xorg-video-dummy \
    xserver-xorg-input-libinput x11-xserver-utils \
    vim nano less curl wget ca-certificates sudo \
    gdb valgrind \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

ENV DEBIAN_FRONTEND=dialog

USER $USERNAME
WORKDIR /workspace
