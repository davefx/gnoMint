# Use Ubuntu as the base image for comprehensive package availability
FROM ubuntu:22.04

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Configure apt and install packages
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config \
    # Version control
    git \
    # GTK+ 3 development files
    libgtk-3-dev \
    # GLib development files
    libglib2.0-dev \
    # GnuTLS development files
    libgnutls28-dev \
    gnutls-bin \
    # SQLite development files
    libsqlite3-dev \
    # libgcrypt development files
    libgcrypt20-dev \
    # readline development files
    libreadline-dev \
    # Additional GTK+ dependencies
    libgdk-pixbuf2.0-dev \
    # Localization tools
    gettext \
    intltool \
    iso-codes \
    # Additional utilities
    vim \
    nano \
    less \
    curl \
    wget \
    ca-certificates \
    gnupg \
    # Development tools
    gdb \
    valgrind \
    # For debugging GTK apps
    libgtk-3-0 \
    dbus-x11 \
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to use
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    # Add sudo support
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Set the default user
USER $USERNAME

# Set working directory
WORKDIR /workspace
