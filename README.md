# GodNS

A fast and configurable attacker-in-the-middle DNS proxy for penetration testers, reverse engineers, and malware analysts inspired by [DNSChef](https://github.com/iphelix/dnschef). It allows the selective replacement of specific DNS records for arbitrary domains with custom values, and can be used to direct traffic to a different host. GodNS can spoof `A`, `AAAA`, `CNAME`, `PTR`, `MX`, `NS`, and `TXT` records.

[![Build Check](https://github.com/moloch--/godns/actions/workflows/build-check.yml/badge.svg)](https://github.com/moloch--/godns/actions/workflows/build-check.yml)
[![Unit Tests](https://github.com/moloch--/godns/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/moloch--/godns/actions/workflows/unit-tests.yml)
[![Release](https://github.com/moloch--/godns/actions/workflows/autorelease.yml/badge.svg)](https://github.com/moloch--/godns/actions/workflows/autorelease.yml)

### Download

Download the [latest release for your platform](https://github.com/moloch--/godns/releases/latest).

### Basic Usage

Basic rules can be passed via the command line and use glob matching for the domain name spoof the response using the provided value. For example, to spoof `A` records for various domains:

```bash
godns --rule-a "microsoft.com|127.0.0.1" --rule-a "google.com|127.0.0.1"
```

You can leverage the glob matching to replace all `A` records for all domains:

```bash
godns --rule-a "*|127.0.0.1"
```

Replace a domain and all subdomain `A` records:

```bash
godns --rule-a "example.com|127.0.0.1" --rule-a "*.example.com|127.0.0.1"
```

### Advanced Usage

For more advanced usage, a config file can be provided. The config file is a JSON or YAML file that contains a list of rules. Configuration file entries support regular expression matching in addition to glob matching. See the example configuration file in this repository for more details. Note that CLI flags override values in the config file if both are provided.

### Supported Platforms

GodNS is a standalone statically compiled binary, and runs on nearly every operating system and CPU architecture:

- Linux (386, amd64, arm64, mips, mips64, mips64le, mipsle, ppc64, ppc64le, riscv64)
- macOS (amd64, arm64)
- Windows (386, amd64, arm64)
- FreeBSD (amd64, arm64)
- OpenBSD (amd64, arm64)
- NetBSD (amd64, arm64)
- DragonFlyBSD (amd64)
- Plan 9 (amd64)
- Solaris (amd64)
- iOS (arm64)
- Android (arm64)
