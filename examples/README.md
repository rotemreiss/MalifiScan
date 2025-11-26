# Malifiscan Examples

This directory provides advanced usage examples and configurations for Malifiscan, demonstrating different deployment scenarios and use cases beyond the basic setup.

## Available Examples

### config.shai-hulud-2.0.yaml

An example configuration that uses a hard-coded list of malicious packages instead of the default OSV feed. This demonstrates how to use the memory feed provider with a specific set of packages.

**Use Case**: Testing against a known set of malicious packages from security research.

**Package List Source**: This example includes packages identified in the [Shai-Hulud 2.0 supply chain attack research by Wiz](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack).

**Features**:
- Memory-based feed provider with pre-defined package list
- JFrog registry integration enabled
- Minimal logging (ERROR level only)
- Storage service disabled for lightweight operation

**Usage**:
```bash
uv run python cli.py scan --config examples/config.shai-hulud-2.0.yaml
```
