# AGENTS.md — AI Agent Guidance & Repository Rules

> **Target Audience**: Autonomous AI Agents (Antigravity, Claude Code, Cursor, Copilot) & Systems Engineers.  
> **Repository**: `arws` (High-Performance Layer 7 Reverse Proxy, Gateway & Load Balancer)  
> **Visibility**: Public Open-Core  
> **Asset Owner**: ALRI Group | **Engineering**: ALRI Development  
> **License**: ARGLP (ALRI Group License Permissive — Version 2)  

---

## 1. Project Mission & Identity

**ARWS** is the native Layer 7 HTTP/HTTPS reverse proxy, load balancer, and API gateway for the ALRIOS platform. It executes as a shared library (`libarws.arlib`) loaded dynamically by the `arcore` supervisor via entry point `arws_entry`.

- **Concurrency Ceiling**: Handles up to **65,536 concurrent connections** (`MAX_CONN`) using non-blocking I/O (`ArPoll`).
- **Worker Pool**: 512 persistent worker threads (`POOL_SIZE`) consuming from a 16,384-slot queue (`QUEUE_SIZE`).
- **Cache Engine**: 16 lock-striped in-memory LRU cache shards (`CACHE_SHARDS = 16`).
- **Load Balancing**: Multi-pool load balancer supporting Smooth WRR, Least Connections, IP Hash, passive circuit breaking, and graceful draining.
- **Port Bindings**: Port `443` (Production TLS 1.3), `8080` (Development/Test HTTP), and `9500` (IPC Control Plane).
- **Reference**: Consult [`DOCS.md`](DOCS.md) for complete 900+ lines technical manual covering all structs and functions.

---

## 2. Essential Commands

### Build as ALRIOS Shared Library
```bash
# Build via GCC into staging directory
gcc -shared -fPIC -O2 \
  -Isrc -I../../ALRIOS/core -I../../ALRIOS/arkernel/include -I../../ALRIOS/arkernel/ipc -I../../ALRIOS/arkernel/os/include \
  -o libarws.arlib \
  src/arws_entry.c src/arws_gateway.c src/arws_utils.c src/arws_config.c src/arws_ratelimit.c \
  src/arws_session.c src/arws_cache.c src/arws_proxy.c src/arws_stream_proxy.c src/arws_upstream.c \
  src/arws_health.c src/modes.c src/router_ex.c src/registry.c src/dispatcher.c src/server.c src/cJSON.c \
  -larkernel -lssl -lcrypto -lpthread
```

### Operational Commands via ALRIOS CLI
```bash
alrios arws status                                         # Inspect mode, ports, connection counts
alrios arws routes                                         # Dump active route table
alrios arws cfg reload                                     # Hot-reload arws.cfg without downtime
alrios arws upstream list                                  # List pools, node health, weights
alrios arws upstream add <pool> <host> <port> [wt] [bkp]   # Dynamically add node
alrios arws upstream drain <pool> <host> <port> [1|0]      # Toggle graceful drain
```

---

## 3. Strict Prohibitions for AI Agents (The "NEVER" List)

- ❌ **NEVER introduce blocking synchronous file I/O on the request path**: All static responses must be served from cache or sendfile.
- ❌ **NEVER disable `TCP_NODELAY`**: Sub-millisecond latency is mandatory; Nagle's algorithm must remain disabled.
- ❌ **NEVER use non-constant-time comparisons on session tokens**: Constant-time comparison (`ct_compare`) is required to prevent timing side-channels.
- ❌ **NEVER trust `X-Forwarded-For` blindly**: Remote IP must be verified against `ARWS_TRUSTED_PROXY` CIDR whitelist.
- ❌ **NEVER commit `.arlib`, `.arapp`, or build directories**: Staging resides outside the Git working tree.

---

## 4. Code Style & Architectural Invariants

- **Language Standard**: Strict C11 (`-std=c11 -O2 -Wall -Wextra`).
- **Anti-Traversal Validation**: All URI paths must pass `server_path_safe()` before processing (blocks `..`, `%2e`, backslashes, null bytes).
- **Cookie & Header Hardening**: Set-Cookie responses must never be cached (`response_has_set_cookie` check).
- **Compulsory File Header**:
  ```c
  /*
   * Copyright (c) 2026 ALRIGROUP and its affiliates.
   * Engineered and maintained by ALRI Development.
   *
   * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
   * found in the LICENSE file in the root directory of this source tree.
   */
  ```

---

## 5. Git Commit Protocol

- Conventional Commits enforced (`feat(proxy): ...`, `fix(cache): ...`, `docs: ...`).
- Mandatory trailer: `Signed-off-by: ALRI Development <dev@alrigroup.com>`.
