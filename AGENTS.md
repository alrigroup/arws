# AGENTS.md — Autonomous AI Agent Operating Protocol & Technical Invariants

> **Target Audience**: Autonomous AI Agents (Antigravity, Claude Code, Cursor, Copilot) & Systems Network Engineers.  
> **Repository**: `arws` (High-Performance Layer 7 Reverse Proxy, API Gateway & Load Balancer)  
> **Visibility**: Public Open-Core  
> **Asset Owner**: ALRI Group | **Engineering**: ALRI Development  
> **License**: ARGLP (ALRI Group License Permissive — Version 2)  
> **Primary Technical Reference**: Consult [`DOCS.md`](DOCS.md) for complete 900+ lines technical manual covering all structs, functions, and routing pipelines.

---

## 1. Project Mission & Identity

**ARWS (ALRI Web Services)** is the native Layer 7 HTTP/HTTPS reverse proxy, load balancer, and API gateway for the ALRIOS platform. It executes as a shared library (`libarws.arlib`) loaded dynamically by the `arcore` supervisor via entry point `arws_entry`.

### Core Architectural Specifications
- **Concurrency Ceiling**: Handles up to **65,536 concurrent connections** (`MAX_CONN`) using non-blocking I/O multiplexing (`ArPoll`).
- **Worker Thread Pool**: 512 persistent worker threads (`POOL_SIZE`) consuming from a 16,384-slot lock-free job queue (`QUEUE_SIZE`).
- **Cache Engine**: 16 lock-striped in-memory LRU cache shards (`CACHE_SHARDS = 16`, `ARWS_CACHE_MAX_ENTRIES = 256` per shard) with configurable TTL (`default: 60s`).
- **Layer 7 Load Balancer (`arws_upstream.c`)**:
  - Up to 64 pools, 32 nodes per pool (`ARWS_MAX_POOLS = 64`, `ARWS_MAX_NODES_PER_POOL = 32`).
  - Algorithms: Smooth Weighted Round-Robin (WRR), Least Connections, IP Consistent Hashing, and Round Robin.
  - Active Health Prober (`arws_health.c`) via asynchronous background thread probing nodes with configurable fall/rise thresholds.
  - Passive Circuit Breaker: Automatically detects 500/502/503/504 errors and timeouts, tripping failed nodes `DOWN`.
  - Graceful Draining: Enables zero-downtime maintenance without dropping established client connections.
- **Port Bindings**: Port `443` (Production TLS 1.3), `8080` (Development HTTP), and `9500` (IPC Control Plane).

---

## 2. Directory Structure & Key Subsystems

```
arws/
├── arws.arappmake           # ALRIOS package manifest & compilation rules
├── DOCS.md                   # Complete 918 lines technical reference manual
├── README.md                 # Public overview & operational guide
├── AGENTS.md                 # This autonomous agent operating protocol
└── src/
    ├── arws_entry.c          # Shared library entry point (arws_entry) and stop hook
    ├── arws_gateway.c        # IPC Admin server (port 9500), route manager, backend registry
    ├── arws_gateway.h        # Backend structs (ArwsBackend, ArwsRoute), gateway prototypes
    ├── arws_proxy.c          # Standard buffered HTTP reverse proxy forwarding
    ├── arws_proxy.h          # Proxy prototypes and timeout declarations
    ├── arws_stream_proxy.c   # Bidirectional streaming proxy (WebSocket, SSE, Chunked)
    ├── arws_stream_proxy.h   # Stream buffer (64 KiB) and streaming prototypes
    ├── arws_cache.c          # 16-shard lock-striped in-memory LRU response cache
    ├── arws_cache.h          # Cache prototypes and key generator (arws_cache_make_key)
    ├── arws_ratelimit.c      # Multi-tier token-window rate limiter & IP temporary blacklisting
    ├── arws_ratelimit.h      # Rate limit rules and check prototypes
    ├── arws_session.c        # In-memory session manager with 256-bit CSPRNG tokens
    ├── arws_session.h        # Session struct (ArwsSession) and constant-time compare
    ├── arws_upstream.c       # Layer 7 load balancer (Smooth WRR, Least Conn, IP Hash)
    ├── arws_upstream.h       # Node struct (ArwsBackendNode), Pool struct (ArwsUpstreamPool)
    ├── arws_health.c         # Asynchronous active TCP health check monitoring thread
    ├── arws_health.h         # Health monitor lifecycle prototypes
    ├── arws_config.c         # Configuration parser (arws.cfg) and 2000ms mtime watchdog
    ├── arws_config.h         # Configuration prototypes and override structs
    ├── modes.c / modes.h     # Operational modes engine (production, test, maintenance)
    ├── router.c / router.h   # Basic route dispatch hash table
    ├── router_ex.c           # Extended router with path specificity ranking and wildcards
    ├── dispatcher.c          # Central request dispatcher (cache lookup, upstream routing)
    ├── server.c / server.h   # Core non-blocking HTTP 1.1 / TLS socket engine with ArPoll
    └── arws_utils.c / .h     # Standardized HTTP response generators (200 to 503, sendfile)
```

---

## 3. Essential Commands & Toolchain Invariants

### 3.1 Compilation as Shared Library (`libarws.arlib`)
```bash
gcc -shared -fPIC -O2 \
  -Isrc -I../../ALRIOS/core -I../../ALRIOS/arkernel/include -I../../ALRIOS/arkernel/ipc -I../../ALRIOS/arkernel/os/include \
  -o libarws.arlib \
  src/arws_entry.c src/arws_gateway.c src/arws_utils.c src/arws_config.c src/arws_ratelimit.c \
  src/arws_session.c src/arws_cache.c src/arws_proxy.c src/arws_stream_proxy.c src/arws_upstream.c \
  src/arws_health.c src/modes.c src/router_ex.c src/registry.c src/dispatcher.c src/server.c src/cJSON.c \
  -L../../ALRIOS/arcore/lib -larkernel -lssl -lcrypto -lpthread
```

### 3.2 Operational CLI Commands (Dispatched via `alrios arws`)
```bash
alrios arws status                                         # Inspect mode, ports, connection counts
alrios arws routes                                         # Dump active route table
alrios arws cfg reload                                     # Hot-reload arws.cfg without downtime
alrios arws upstream list                                  # List pools, node health (UP/DOWN), weights
alrios arws upstream add <pool> <host> <port> [wt] [bkp]   # Dynamically register backend node
alrios arws upstream drain <pool> <host> <port> [1|0]      # Toggle graceful drain for maintenance
alrios arws global maintenance                             # Switch to maintenance mode
alrios arws global production                              # Return to production mode
```

---

## 4. Architectural Rules & The "NEVER" List

Autonomous AI Agents operating within this codebase must strictly observe these inviolable rules:

### 4.1 Strict Prohibitions
- ❌ **NEVER introduce blocking I/O on worker threads**: Worker threads in `server.c` must process non-blocking requests. Synchronous disk file reading during request dispatching is prohibited (use cache or sendfile).
- ❌ **NEVER disable `TCP_NODELAY`**: Sub-millisecond proxy response latency is mandatory; Nagle's algorithm must always be disabled on accepted sockets.
- ❌ **NEVER compare session tokens or hashes with `strcmp()` or `memcmp()`**: Use constant-time comparison (`ct_compare()`) to prevent remote timing side-channel attacks.
- ❌ **NEVER cache HTTP responses containing `Set-Cookie`**: Responses carrying session cookies must never be stored in `arws_cache` (`response_has_set_cookie` invariant) to prevent account hijacking.
- ❌ **NEVER trust `X-Forwarded-For` without CIDR validation**: The client IP must only be resolved from forwarded headers if the immediate peer IP matches an entry in `ARWS_TRUSTED_PROXY`.
- ❌ **NEVER allow unescaped CRLF characters in HTTP response headers**: All header keys and values must be stripped of `\r` and `\n` before emission to eliminate HTTP Response Splitting attacks.

---

## 5. Code Style & Engineering Standards

### 5.1 Correct vs. Incorrect Implementations

#### Anti-Path Traversal & Safe Path Resolution
```c
/* FORBIDDEN: Incomplete check vulnerable to encoded traversal and null byte truncation */
if (strstr(req->path, "..") != NULL) {
    server_send_404(conn);
}

/* CORRECT (ARWS Standard): Multi-layer path safety evaluation */
int server_path_safe(const char *path) {
    if (!path || path[0] == '\0') return 0;
    if (strstr(path, "..") || strstr(path, "%2e") || strstr(path, "%2E")) return 0;
    if (strchr(path, '\\') || strstr(path, "%5c") || strstr(path, "%5C")) return 0;
    for (const char *p = path; *p; p++) {
        if ((unsigned char)*p < 0x20 || *p == 0x7F) return 0;
    }
    return 1;
}
```

#### Constant-Time Token Evaluation
```c
/* CORRECT (ARWS Standard): Constant-time byte-by-byte comparison */
static int ct_compare(const char *a, const char *b) {
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int diff = (la != lb);
    size_t min = la < lb ? la : lb;
    for (size_t i = 0; i < min; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}
```

### 5.2 Mandatory Copyright Header
Every new C source or header file created must begin with:
```c
/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */
```

---

## 6. Pre-Commit & Pull Request Verification Checklist

Before submitting changes, the agent must verify:
1. `libarws.arlib` compiles cleanly with zero warnings under `-O2 -Wall -Wextra`.
2. Any newly registered route properly handles wildcard matching (`/*`) and path specificity rankings in `router_ex.c`.
3. Upstream node health state transitions (UP/DOWN) are covered by mutex synchronization (`pool->lock`).
4. Response caching adheres to `no-cache` directives and Set-Cookie prevention.
5. Git commits adhere to Conventional Commits with the mandatory trailer:
   `Signed-off-by: ALRI Development <dev@alrigroup.com>`.
