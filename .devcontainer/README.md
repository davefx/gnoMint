# gnoMint Development Container

This directory contains the configuration for a development container that provides a complete, pre-configured development environment for gnoMint using Visual Studio Code Dev Containers.

## What's Included

The development container includes all the necessary tools and dependencies to build and develop gnoMint:

### Build Tools
- GCC (GNU Compiler Collection)
- GNU Make
- Autoconf
- Automake
- Libtool
- pkg-config

### Required Libraries
- **GTK+ 3.10.0+**: GUI toolkit
- **GLib 2.32.0+**: Core application building blocks
- **GnuTLS 2.0+**: TLS/SSL library
- **SQLite 3.0+**: Database engine
- **libgcrypt 1.2.0+**: Cryptographic library
- **libreadline**: Command-line editing library

### Development Tools
- Git
- GDB (GNU Debugger)
- Valgrind (memory debugging)
- Text editors (vim, nano)

### Localization Tools
- gettext
- intltool
- iso-codes

### VS Code Extensions
- C/C++ Extension Pack
- GitHub Copilot
- GitHub Copilot Chat

## Using the Development Container

### Prerequisites
- [Visual Studio Code](https://code.visualstudio.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for VS Code

### Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/davefx/gnoMint.git
   cd gnoMint
   ```

2. Open the repository in VS Code:
   ```bash
   code .
   ```

3. When prompted, click "Reopen in Container" or use the command palette (F1) and select "Dev Containers: Reopen in Container"

4. Wait for the container to build (first time may take several minutes)

5. Once the container is ready, you can build gnoMint:
   ```bash
   ./autogen.sh
   ./configure
   make
   ```

## Building gnoMint

After the container is set up, you can build the project using the standard autotools workflow:

```bash
# Generate the configure script
./autogen.sh

# Configure the build
./configure

# Build the project
make

# (Optional) Install the application
sudo make install
```

## Customization

You can customize the development container by editing:
- `devcontainer.json`: VS Code settings and extensions
- `Dockerfile`: System packages and dependencies
- `post-create.sh`: Commands to run after container creation

## Troubleshooting

### Container fails to build
- Ensure Docker is running
- Check your internet connection
- Try rebuilding the container: Command Palette → "Dev Containers: Rebuild Container"

### Missing dependencies
If you encounter missing dependencies, you can install them in the running container:
```bash
sudo apt-get update
sudo apt-get install <package-name>
```

Then update the `Dockerfile` to include them permanently.

## Additional Resources

- [VS Code Dev Containers Documentation](https://code.visualstudio.com/docs/devcontainers/containers)
- [gnoMint Project Website](http://gnomint.sourceforge.net)
- [GTK+ Documentation](https://docs.gtk.org/)
- [GnuTLS Documentation](https://www.gnutls.org/documentation.html)
