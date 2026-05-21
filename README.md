# pia-wg-config

A fast, portable Wireguard config generator for Private Internet Access (PIA) VPN.

[![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/doc/devel/release)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌍 Region Selection (NOT Hardcoded!)

**IMPORTANT:** This tool supports ALL PIA regions through the `-r/--region` flag. The default region is `us_california`, but you can easily connect to any region:

```bash
# Connect to different regions
pia-wg-config -r uk_london USERNAME PASSWORD
pia-wg-config -r de_frankfurt USERNAME PASSWORD  
pia-wg-config -r au_sydney USERNAME PASSWORD
pia-wg-config -r japan USERNAME PASSWORD
```

### List All Available Regions

To see all available regions before connecting:

```bash
pia-wg-config regions
```

This will show you the complete list of PIA server regions you can connect to.

## 🚀 Quick Start

### Install Go

#### Linux

```bash
sudo apt-get update && sudo apt-get install golang-go

# define go installation location and add to path
go env -w GOPATH=$HOME/go
echo "export GOPATH=\$HOME/go" >> ~/.bash_profile
echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.bash_profile
source ~/.bash_profile
```

#### macOS

```bash
brew install go

# define go installation location and add to path
go env -w GOPATH=$HOME/go
echo "export GOPATH=\$HOME/go" >> ~/.zshenv
echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.zshenv
source ~/.zshenv
```

### Install pia-wg-config

```bash
go build -o pia-wg-config .
```

### Basic Usage

```bash
# Generate config for default region (us_california)
pia-wg-config USERNAME PASSWORD

# Generate config for a specific region
pia-wg-config -r uk_london USERNAME PASSWORD

# Save config to file
pia-wg-config -o wg0.conf -r de_frankfurt USERNAME PASSWORD

# Enable verbose output
pia-wg-config -v -r japan USERNAME PASSWORD

# Use environment variables instead of positional arguments (useful in scripts)
export PIAWGCONFIG_USER=myusername
export PIAWGCONFIG_PW=mypassword
pia-wg-config -r uk_london

# Supply the PIA CA cert from a trusted local copy instead of downloading it at runtime.
# Recommended for security-sensitive environments to eliminate the TOFU risk
# of fetching the cert from GitHub on first use.
pia-wg-config -c /path/to/pia-ca.crt -r uk_london USERNAME PASSWORD
```

## 📖 Command Reference

### Main Command

```
pia-wg-config [OPTIONS] USERNAME PASSWORD
```

**Arguments:**
- `USERNAME` - Your PIA username
- `PASSWORD` - Your PIA password

**Options:**
- `-r, --region` - Region to connect to (default: "us_california")
- `-o, --outfile` - Output file for the config (default: stdout)
- `-c, --ca-cert` - Path to a locally-trusted PEM CA certificate file for verifying PIA's WireGuard API endpoint. When omitted, the cert is fetched from GitHub at runtime and verified against a pinned SHA-256 fingerprint — supply this flag to eliminate that runtime-download trust dependency in security-sensitive environments.
- `-v, --verbose` - Enable verbose output
- `-h, --help` - Show help

**Environment variables (alternative to positional arguments):**
- `PIAWGCONFIG_USER` - PIA username (overridden by positional `USERNAME` argument if both are supplied)
- `PIAWGCONFIG_PW` - PIA password (overridden by positional `PASSWORD` argument if both are supplied)

### Subcommands

- `pia-wg-config regions` - List all available PIA regions

## 🌐 Popular Regions

Here are some commonly used region codes:

| Region Code | Location |
|-------------|----------|
| `us_california` | United States - California |
| `us_east` | United States - East Coast |
| `uk_london` | United Kingdom - London |
| `de_frankfurt` | Germany - Frankfurt |
| `ca_toronto` | Canada - Toronto |
| `au_sydney` | Australia - Sydney |
| `japan` | Japan |
| `singapore` | Singapore |
| `netherlands` | Netherlands |
| `sweden` | Sweden |

Run `pia-wg-config regions` for the complete list.

## 💡 Usage Examples

### Connect to UK servers
```bash
pia-wg-config -r uk_london -o uk-wg.conf myusername mypassword
sudo wg-quick up uk-wg.conf
```

### Connect to German servers
```bash
pia-wg-config -r de_frankfurt -o germany.conf myusername mypassword
sudo wg-quick up germany.conf
```

### Quick connection (output to stdout)
```bash
pia-wg-config -r netherlands myusername mypassword > vpn.conf
```

## 🔧 Integration Examples

### Bash Script for Multiple Regions
```bash
#!/bin/bash
REGIONS=("uk_london" "de_frankfurt" "us_california" "japan")
USERNAME="your_username"
PASSWORD="your_password"

for region in "${REGIONS[@]}"; do
    echo "Generating config for $region..."
    pia-wg-config -r "$region" -o "configs/${region}.conf" "$USERNAME" "$PASSWORD"
done
```

### Docker Usage
```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/pia-wg-config .

FROM alpine:latest
RUN apk --no-cache add ca-certificates wireguard-tools
COPY --from=builder /usr/local/bin/pia-wg-config /usr/local/bin/
ENTRYPOINT ["pia-wg-config"]
```

## 🏗️ Building from Source

```bash
go build -o pia-wg-config .
```

## 🐛 Troubleshooting

### Common Issues

**"Region not found" error:**
- Run `pia-wg-config regions` to see available regions
- Check your spelling of the region code
- Region codes are case-sensitive

**Authentication errors:**
- Verify your PIA username and password
- Make sure your PIA subscription is active
- Try connecting through the PIA app first to verify credentials

**Network connectivity issues:**
- Check your internet connection
- Try with verbose mode: `-v` flag
- Some networks block VPN traffic

### Getting Help

1. Run with `-v` flag for detailed output
2. Verify your PIA account is active
3. Search the repository history for recent changes

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
go mod download
go test ./...
```

## 📋 Requirements

- Go 1.25 or later (for building)
- Active PIA subscription
- Wireguard client (for using generated configs)

## 🔐 Security

- This tool connects directly to PIA's official API endpoints
- Your credentials are only used for authentication and are not stored
- Generated configs contain your unique keys - keep them secure
- Configs expire and need to be regenerated periodically

## 📚 Background

Based on the [manual-connections](https://github.com/pia-foss/manual-connections) scripts provided by Private Internet Access. This Go implementation provides:

- **Portability** - Single binary that runs anywhere
- **Speed** - Fast config generation
- **Reliability** - No external dependencies
- **Simplicity** - Easy command-line interface

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Star History

If this tool helped you, consider giving it a star! It helps others discover the project.

---

**Note for Forkers:** You don't need to fork this repository to change regions! Use the `-r` flag instead. This tool supports all PIA regions out of the box.
