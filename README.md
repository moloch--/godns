# GodNS

A configurable attacker-in-the-middle DNS proxy for Penetration Testers and Malware Analysts, inspired by [DNSChef](https://github.com/iphelix/dnschef). It allows the selective replacement of specific DNS records for arbitrary domains with custom values, and can be used to direct traffic to a different host.

[![Build Check](https://github.com/moloch--/godns/actions/workflows/build-check.yml/badge.svg)](https://github.com/moloch--/godns/actions/workflows/build-check.yml)

### Basic Usage

Basic rules can be passed via the command line, basic rules simply match a domain name for a record type
and spoof the response using the provided value. For example, to spoof all `A` records for various domains:

```bash
godns --rule-a "microsoft.com|127.0.0.1" --rule-a "google.com|127.0.0.1"
```

One special case is allowed for the command line, if the value is set to `*` then all records are spoofed for
associated record type. For example, to spoof all `A` and `AAAA` records for all domains:

```bash
godns --rule-a "*|127.0.0.1" --rule-aaaa "*|::1"
```

### Advanced Usage

For more advanced usage, a config file can be provided. The config file is a JSON or YAML file that
contains a list of rules. Each rule has a match and spoof value, and can optionally specify a record type
and priority. Configuration file also allow for regular expression matching, and can be used to spoof
multiple records for a single domain.

### Support Platforms

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
