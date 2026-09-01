<p align="center">
  <img src="https://raw.githubusercontent.com/alrigroup/.github/main/alrigroup.svg" width="120" />
</p>

<h1 align="center">ARWS</h1>
<p align="center"><strong>High-Performance Reverse Proxy, Load Balancer & Stream Proxy</strong></p>
<p align="center">
  <a href="https://github.com/alrigroup/alrios"><img alt="ALRIOS" src="https://img.shields.io/badge/Powered%20by-ALRIOS-blue?style=flat-square" /></a>
  <img alt="Language" src="https://img.shields.io/badge/language-C-00599C?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" />
</p>

---

## Overview

**ARWS** (ALRI Web Server) is a native C reverse proxy and load balancer built on top of the [ALRIOS](https://github.com/alrigroup/alrios) kernel. It is designed for high-throughput, low-latency production workloads.

### Features

- 🔄 **Reverse Proxy** — Route traffic to upstream backends with automatic health checks
- ⚖️ **Load Balancing** — Round-robin and weighted upstream distribution
- 🔌 **Stream Proxy** — Raw TCP/TLS stream proxying for databases & services
- 🛡️ **Rate Limiting** — Per-IP and per-route configurable rate limiting
- 🧊 **Response Caching** — In-memory cache for static and dynamic responses
- 🔒 **TLS Termination** — Native OpenSSL integration for HTTPS endpoints
- 📡 **Gateway Mode** — Acts as the central API gateway for all ALRIOS services
- 🏠 **Built-in Home** — Default landing page and 404/maintenance pages

## Building

Requires the [ALRIOS SDK](https://github.com/alrigroup/alrios) installed:

```bash
armake build arws
```

## Architecture

ARWS runs as a shared library (`libarws.arlib`) loaded by the ALRIOS service manager. It registers routes dynamically and proxies requests to upstream applications.

## Part of ALRIOS

ARWS is a core component of the [ALRIOS Operating System](https://github.com/alrigroup/alrios).

---

<p align="center">© 2025 ALRI Group — All rights reserved.</p>
