# ARWS — Technical Reference Manual

*ALRI Web Services — High-Performance Reverse Proxy, Gateway & Load Balancer*

*Version: 0.2.01 | Engineered by ALRI Development | Governed by ALRI GROUP © 2026 | License: ARGLP*

---

## Table of Contents

- [1. Overview & Ecosystem Placement](#1-overview--ecosystem-placement)
- [2. Architecture & Internal Request Pipeline](#2-architecture--internal-request-pipeline)
- [3. Configuration Reference](#3-configuration-reference)
  - [3.1 arws.cfg Keys](#31-arwscfg-keys)
  - [3.2 Environment Variables](#32-environment-variables)
  - [3.3 Route & Override Syntax](#33-route--override-syntax)
  - [3.4 Config Watchdog (Hot Reload)](#34-config-watchdog-hot-reload)
- [4. Module Reference](#4-module-reference)
  - [4.1 Gateway Core (arws_gateway + arws_entry)](#41-gateway-core)
  - [4.2 HTTP Server & Network Stack (server)](#42-http-server--network-stack)
  - [4.3 Reverse Proxy (arws_proxy)](#43-reverse-proxy)
  - [4.4 Stream Proxy (arws_stream_proxy)](#44-stream-proxy)
  - [4.5 In-Memory Cache Engine (arws_cache)](#45-in-memory-cache-engine)
  - [4.6 Rate Limiting Engine (arws_ratelimit)](#46-rate-limiting-engine)
  - [4.7 Session Manager (arws_session)](#47-session-manager)
  - [4.8 Upstream Load Balancer (arws_upstream)](#48-upstream-load-balancer)
  - [4.9 Health Check Monitor (arws_health)](#49-health-check-monitor)
  - [4.10 Router & Extended Router (router + router_ex)](#410-router--extended-router)
  - [4.11 Operational Modes & Config (modes + arws_config)](#411-operational-modes--config)
  - [4.12 Dispatcher (dispatcher)](#412-dispatcher)
  - [4.13 IPC Control Plane (ipc_pipe)](#413-ipc-control-plane)
  - [4.14 Legacy BEMF & API Plugin (bemf + api)](#414-legacy-bemf--api-plugin)
  - [4.15 Utilities & HTTP Responses (arws_utils)](#415-utilities--http-responses)
- [5. IPC Protocol Specification](#5-ipc-protocol-specification)
- [6. Security Model](#6-security-model)
- [7. Operational Guide & CLI Reference](#7-operational-guide--cli-reference)
- [8. Build & Packaging](#8-build--packaging)

---

## 1. Overview & Ecosystem Placement

**ARWS (ALRI Web Services)** is the Layer 7 HTTP/HTTPS reverse proxy, API gateway, and load balancer that sits at the front of the entire ALRIOS platform. Every inbound request from the public internet passes through ARWS before reaching any application, CDN, database API, or web native container.

### Key Capabilities

| Capability | Specification |
|---|---|
| Max Concurrent Connections | **65,536** (`MAX_CONN`) |
| Worker Thread Pool | **512** threads (`POOL_SIZE`) |
| Job Queue Depth | **16,384** (`QUEUE_SIZE`) |
| Cache Shards | **16** lock-striped shards (`CACHE_SHARDS`) |
| Upstream Pools | Up to **64** pools, **32** nodes per pool |
| Load Balancing Algorithms | Smooth WRR, Least Connections, IP Hash, Round Robin |
| TLS Termination | TLS 1.3 via OpenSSL |
| Rate Limiting | IP-based token window + per-route custom rules |

### Ecosystem Role

```
                    ┌──────────────────┐
                    │  Client Browser  │
                    └────────┬─────────┘
                             │ HTTP (8080) / HTTPS (443)
                    ┌────────▼─────────┐
                    │      ARWS        │ ← You are here
                    │ (Reverse Proxy)  │
                    └───┬───┬───┬──────┘
                        │   │   │ IPC (9500) + Upstream Pools
              ┌─────────┘   │   └──────────┐
              ▼             ▼              ▼
          ┌───────┐   ┌──────────┐   ┌──────────┐
          │ arwn  │   │  arcdn   │   │  ardb    │
          │ .arweb│   │  static  │   │  PGWire  │
          └───────┘   └──────────┘   └──────────┘
```

---

## 2. Architecture & Internal Request Pipeline

### Request Processing Flow

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │                          ARWS Internal Pipeline                             │
 │                                                                             │
 │  Client ──► Listener (ArPoll) ──► Accept ──► Thread Pool (512 workers)     │
 │                                                    │                        │
 │                                          ┌─────────▼──────────┐             │
 │                                          │  HTTP 1.1 Parser   │             │
 │                                          │  URL Decode (2x)   │             │
 │                                          │  Path Sanitization │             │
 │                                          │  Header Extraction │             │
 │                                          └─────────┬──────────┘             │
 │                                                    │                        │
 │                                          ┌─────────▼──────────┐             │
 │                                          │   Rate Limiter     │             │
 │                                          │  (IP + Route Rule) │             │
 │                                          └─────────┬──────────┘             │
 │                                                    │                        │
 │                                          ┌─────────▼──────────┐             │
 │                                          │ Effective Mode     │             │
 │                                          │ (prod/test/maint)  │             │
 │                                          │ Override by Route  │             │
 │                                          └─────────┬──────────┘             │
 │                                                    │                        │
 │                                          ┌─────────▼──────────┐             │
 │                                          │    Dispatcher      │             │
 │                                          └──┬──┬──┬──┬──┬─────┘             │
 │                                             │  │  │  │  │                   │
 │     ┌───────────────┐  ┌──────────┐  ┌──────┘  │  │  │  └──────┐           │
 │     │ Local Handler │  │ Redirect │  │ Upstream │  │  │ Stream  │           │
 │     │ (result=2)    │  │ (301/302)│  │ Pool LB  │  │  │ Proxy   │           │
 │     └───────────────┘  └──────────┘  └──────────┘  │  └─────────┘           │
 │                                                    │                        │
 │                                          ┌─────────▼──────────┐             │
 │                                          │   Cache Layer      │             │
 │                                          │  (16 shards LRU)   │             │
 │                                          └────────────────────┘             │
 └──────────────────────────────────────────────────────────────────────────────┘
```

### Concurrency Model

- **Event Loop**: `ArPoll` (epoll on Linux / WSAPoll on Windows) monitors the listener socket for new connections with burst accept.
- **Thread Pool**: 512 persistent worker threads consume jobs from a lock-free queue of 16,384 slots. Each worker processes one HTTP request to completion.
- **Socket I/O**: Non-blocking sockets with `O_NONBLOCK`, `TCP_NODELAY`, `SO_REUSEADDR`, and configurable read timeouts (`ARWS_READ_TIMEOUT_MS = 10000`).
- **TLS**: OpenSSL context initialized once; each accepted connection is wrapped with `SSL_new()` + `SSL_accept()`. A dedicated redirector thread on port 80 returns `301 Moved Permanently` to HTTPS.

---

## 3. Configuration Reference

### 3.1 arws.cfg Keys

The configuration file is located at `arcore/storage/arws/arws.cfg` (resolved via `resolve_config_path()`).

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"production"` | Operating mode: `production` (HTTPS/443) or `test` (HTTP/8080) |
| `port` | int | `443` (prod) / `8080` (test) | Primary listen port |
| `bind` | string | `"0.0.0.0"` (prod) / `"127.0.0.1"` (test) | Bind address |
| `global_mode` | string | `"production"` | Global operational mode: `production`, `test`, or `maintenance` |
| `maintenance_ips` | JSON array | `[]` | IPs allowed to bypass maintenance mode |
| `cache_ttl` | int | `60` | Cache entry time-to-live in seconds |

### 3.2 Environment Variables

| Variable | Type | Description |
|---|---|---|
| `ARWS_MODE` | string | Override `mode` from config (`production` or `test`) |
| `ARWS_PORT` | int | Override listen port |
| `ARWS_TRUSTED_PROXY` | CIDR list | Comma-separated trusted proxy CIDRs for `X-Forwarded-For` parsing |
| `BEHIND_CLOUDFLARE` | `1`/`0` | Enable `CF-Connecting-IP` header trust |
| `TRUSTED_DOMAIN` | string | Domain considered trusted for CORS and header forwarding |
| `ARWS_STAY_ROOT` | `1`/`0` | Prevent privilege drop after binding to port 443 |
| `SUDO_UID` / `SUDO_GID` | int | Target UID/GID for privilege drop |

### 3.3 Route & Override Syntax

Routes and operational overrides are defined inline in `arws.cfg` using quoted strings:

```ini
# Operational mode override (per host/path)
"myapp.example.com/*" = maintenance
"myapp.example.com/api/*" = production no-cache

# HTTP Reverse Proxy route
"myapp.example.com/api/*" = "http://127.0.0.1:3090"

# Stream Proxy route (WebSocket / SSE / Chunked)
"myapp.example.com/ws/*" = stream "http://127.0.0.1:3091"
```

### 3.4 Config Watchdog (Hot Reload)

A background thread (`config_watchdog_loop`) polls the `arws.cfg` file `mtime` every **2,000ms** (`CONFIG_POLL_MS`). If modified, the file is re-parsed and all routes, overrides, and settings are reloaded without downtime.

---

## 4. Module Reference

### 4.1 Gateway Core

**Files**: `arws_entry.c`, `arws_gateway.c`, `arws_gateway.h`

**Purpose**: Entry point for the ARWS service. Initializes all subsystems, starts the HTTP server, manages the IPC admin port (9500), and handles backend registration/routing.

#### Structs

```c
typedef struct {
    int id;                    // Backend identifier
    int fd;                    // Socket file descriptor (IPC pipe)
    int pid;                   // Backend process PID
    char name[64];             // Backend name (e.g., "arcdn")
    int registered;            // 1 = active, 0 = inactive
} ArwsBackend;

typedef struct {
    char prefix[256];          // URL prefix (e.g., "/api/*")
    char method[16];           // HTTP method filter ("GET", "*")
    char host[256];            // Virtual host domain
    char mode[16];             // Operational mode for this route
    int backend_id;            // Associated backend ID
    int use_handler;           // 1 = local handler function
    int use_stream;            // 1 = stream proxy mode
    int use_redirect;          // 1 = HTTP redirect
    char proxy_target[256];    // Upstream URL for proxy
    char redirect_target[256]; // Redirect destination URL
    RequestHandler handler;    // Function pointer for local handlers
} ArwsRoute;
```

#### Functions

| Signature | Description |
|---|---|
| `int arws_init(void)` | Initialize all subsystems (cache, rate limiter, sessions, upstream pools, config) |
| `int arws_start(int port, int mode)` | Start the HTTP/TLS server on `port` with `mode` (0=insecure, 1=secure) |
| `void arws_stop(void)` | Graceful shutdown: stop health checks, config watchdog, server |
| `void arws_entry(int ipc_fd)` | Main entry point called by arcore when loading the shared library |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARWS_ADMIN_PORT` | `9500` | IPC control channel port |
| `ARWS_MAX_BACKENDS` | `64` | Maximum registered IPC backends |
| `ARWS_MAX_ROUTES` | `512` | Maximum registered routes |

---

### 4.2 HTTP Server & Network Stack

**Files**: `server.c`, `server.h`

**Purpose**: Core TCP/TLS server with non-blocking I/O, ArPoll event loop, thread pool, HTTP 1.1 parser, trusted proxy resolution, and response utilities.

#### Structs

```c
typedef struct {
    const char *name;
    const char *value;
} HttpHeader;

typedef struct {
    const char *key;
    const char *value;
} PathParam;

typedef struct {
    const char *key;
    const char *value;
} QueryParam;

typedef struct {
    char *method;              // "GET", "POST", etc.
    char *path;                // Decoded URL path
    char *query_params;        // Raw query string
    char *cookies;             // Cookie header value
    char *body;                // Request body (POST/PUT)
    HttpHeader headers[100];   // Parsed headers (max 100)
    int header_count;
    PathParam path_params[20]; // Route parameters
    int path_param_count;
    QueryParam parsed_query[50]; // Parsed query params
    int query_count;
    cJSON *json_doc;           // Parsed JSON body (if Content-Type: application/json)
    int body_length_in_buffer;
} HttpRequest;
```

#### Functions

| Signature | Description |
|---|---|
| `int server_start(int port, int mode, RequestHandler handler)` | Start TCP listener on `port`, dispatch requests to `handler` |
| `void server_stop(void)` | Signal all workers to terminate and close listener |
| `void server_send_response(ClientConnection *conn, int status, const char *content_type, const char *body, int body_len)` | Send full HTTP response with headers |
| `void server_add_header(ClientConnection *conn, const char *name, const char *value)` | Append custom response header |
| `void server_redirect(ClientConnection *conn, int status, const char *url)` | Send 301/302 redirect response |
| `const char* server_get_client_ip(ClientConnection *conn)` | Get resolved client IP (supports trusted proxy chain) |
| `void server_serve_file(ClientConnection *conn, const char *path, const char *mime)` | Serve file from disk with zero-copy sendfile |
| `void server_send_404(ClientConnection *conn)` | Send standard 404 response |
| `cJSON* parse_json_body(HttpRequest *req)` | Parse request body as JSON |
| `void server_send_json(ClientConnection *conn, int status, cJSON *json)` | Serialize and send JSON response |
| `const char* get_header(HttpRequest *req, const char *name)` | Lookup request header by name (case-insensitive) |
| `const char* get_path_param(HttpRequest *req, const char *name)` | Lookup route path parameter |
| `const char* get_query_param(HttpRequest *req, const char *name)` | Lookup query string parameter |
| `void server_set_bind_address(const char *addr)` | Set server bind address before start |
| `void server_set_logger(void (*fn)(const char *, ...))` | Set custom logger function |
| `int server_path_safe(const char *path)` | Validate path against traversal attacks (returns 0 if unsafe) |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_CONN` | `65536` | Maximum concurrent TCP connections |
| `MAX_POLL_EVENTS` | `1024` | Maximum events per ArPoll cycle |
| `ARWS_READ_TIMEOUT_MS` | `10000` | Socket read timeout (10 seconds) |
| `MAX_CONNECTIONS` | `65536` | Connection ceiling (503 at saturation) |
| `POOL_SIZE` | `512` | Worker threads in the pool |
| `QUEUE_SIZE` | `16384` | Job queue depth |
| `ARWS_MAX_TRUSTED_PROXIES` | `32` | Maximum trusted proxy CIDR entries |
| `MODE_INSECURE` | `0` | HTTP mode |
| `MODE_SECURE` | `1` | HTTPS mode (TLS termination) |

---

### 4.3 Reverse Proxy

**Files**: `arws_proxy.c`, `arws_proxy.h`

**Purpose**: Forward HTTP requests to upstream backends, receive the full response, and return it to the client. Used for traditional HTTP reverse proxy with buffered responses.

#### Functions

| Signature | Description |
|---|---|
| `int arws_proxy_init(void)` | Initialize connection pool for reuse |
| `int arws_proxy_forward(const char *target_url, const unsigned char *raw_req, int raw_len, unsigned char *out_resp, int max_resp_len)` | Forward raw HTTP request to `target_url`, store response in `out_resp`. Returns response length or -1 on error |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARWS_PROXY_TIMEOUT_MS` | `10000` | Upstream connection timeout (10s) |

---

### 4.4 Stream Proxy

**Files**: `arws_stream_proxy.c`, `arws_stream_proxy.h`

**Purpose**: Bidirectional stream proxy for WebSocket, Server-Sent Events (SSE), and HTTP chunked transfer. Unlike the buffered proxy, this pipes data in both directions simultaneously.

#### Functions

| Signature | Description |
|---|---|
| `int arws_stream_proxy_forward(ClientConnection *conn, HttpRequest *req, const char *target_url)` | Establish bidirectional stream between client and upstream. Returns 0 on success |
| `int arws_build_http_request(ClientConnection *conn, HttpRequest *req, unsigned char *buf, int bufsize)` | Serialize the original HTTP request into a raw buffer for upstream forwarding |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARWS_STREAM_BUF_SIZE` | `65536` | I/O buffer size for stream piping (64 KiB) |
| `ARWS_STREAM_TIMEOUT_MS` | `30000` | Stream idle timeout (30 seconds) |

---

### 4.5 In-Memory Cache Engine

**Files**: `arws_cache.c`, `arws_cache.h`

**Purpose**: 16-shard lock-striped in-memory LRU cache for full HTTP responses. Each shard has its own mutex, enabling concurrent access without global lock contention.

#### Functions

| Signature | Description |
|---|---|
| `void arws_cache_init(void)` | Initialize all 16 shards with empty hash tables |
| `void arws_cache_set_ttl(int seconds)` | Set the global cache TTL |
| `int arws_cache_get_ttl(void)` | Get current TTL value |
| `int arws_cache_get(const char *key, unsigned char **out_data, int *out_len)` | Lookup cache entry by key. Returns 1 if found (copies data to `out_data`), 0 if miss |
| `int arws_cache_set(const char *key, const unsigned char *data, int len)` | Store response in cache. Evicts LRU entry if shard is full |
| `void arws_cache_clear(void)` | Flush all 16 shards immediately |
| `void arws_cache_cleanup(void)` | Remove expired entries from all shards |
| `void arws_cache_make_key(char *out, int out_size, const char *method, const char *host, const char *path, const char *query)` | Generate deterministic cache key from request components |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `CACHE_SHARDS` | `16` | Number of independent cache partitions |
| `ARWS_CACHE_MAX_ENTRIES` | `256` | Maximum entries per shard |
| `ARWS_CACHE_DEFAULT_TTL` | `60` | Default entry lifetime in seconds |

---

### 4.6 Rate Limiting Engine

**Files**: `arws_ratelimit.c`, `arws_ratelimit.h`

**Purpose**: Multi-tier rate limiting with IP-based token windows and per-route custom rules. Supports temporary IP blacklisting.

#### Functions

| Signature | Description |
|---|---|
| `void arws_ratelimit_init(void)` | Initialize rate limiting state |
| `void arws_ratelimit_set_rule(const char *host, const char *path_pattern, int max_req, int window_sec)` | Define a custom rate limit rule for a specific host/path pattern |
| `int arws_ratelimit_check(const char *ip, const char *host, const char *path)` | Check if request from `ip` to `host/path` is within rate limit. Returns 0 = allowed, 1 = rate limited (429) |
| `int arws_ratelimit_check_ip(const char *ip)` | Check global IP-only rate limit (no route context) |
| `void arws_ratelimit_block_ip(const char *ip, int seconds)` | Temporarily blacklist an IP for `seconds` |
| `int arws_ratelimit_is_blocked(const char *ip)` | Check if IP is currently blacklisted. Returns 1 if blocked |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARWS_RL_MAX_IPS` | `2000` | Maximum tracked IPs |
| `ARWS_RL_MAX_RULES` | `64` | Maximum custom rules |
| `ARWS_RL_DEFAULT_MAX` | `5000` | Default: 5000 requests per window |
| `ARWS_RL_DEFAULT_WINDOW` | `60` | Default window: 60 seconds |

---

### 4.7 Session Manager

**Files**: `arws_session.c`, `arws_session.h`

**Purpose**: In-memory session storage with CSPRNG token generation (OpenSSL `RAND_bytes`), IP binding, constant-time token comparison (anti timing-attack), and automatic expiration.

#### Structs

```c
typedef struct {
    char token[128];       // CSPRNG hex token (256-bit)
    char user[64];         // Associated username
    char ip[64];           // Bound client IP
    int role;              // Role level (0=user, 1=admin, etc.)
    uint64_t created_at;   // Creation timestamp (ms)
    uint64_t expires_at;   // Expiration timestamp (ms)
    int valid;             // 1 = active, 0 = destroyed
} ArwsSession;
```

#### Functions

| Signature | Description |
|---|---|
| `void arws_session_init(void)` | Initialize session storage |
| `ArwsSession* arws_session_create(const char *user, const char *ip, int role, int ttl_seconds)` | Create new session with CSPRNG token. Returns session pointer |
| `ArwsSession* arws_session_verify(const char *token, const char *ip)` | Verify token with constant-time compare + IP match. Returns session or NULL |
| `int arws_session_destroy(const char *token)` | Invalidate session by token |
| `void arws_session_cleanup(void)` | Remove all expired sessions |
| `void arws_session_generate_token(char *buf, int len)` | Generate cryptographically secure random hex token |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARWS_MAX_SESSIONS` | `1024` | Maximum concurrent sessions |

---

### 4.8 Upstream Load Balancer

**Files**: `arws_upstream.c`, `arws_upstream.h`

**Purpose**: Multi-pool Layer 7 load balancer with 4 distribution algorithms, backup/contingency nodes, passive circuit breaker, and graceful draining.

#### Enums

```c
typedef enum {
    ARWS_LB_ROUND_ROBIN,           // Simple round-robin
    ARWS_LB_WEIGHTED_ROUND_ROBIN,  // Smooth WRR (Nginx-grade)
    ARWS_LB_LEAST_CONN,            // Least active connections
    ARWS_LB_IP_HASH                // Consistent hashing by client IP
} ArwsLbAlgo;
```

#### Structs

```c
typedef struct {
    char id[64];              // Node identifier (e.g., "srv-01")
    char host[128];           // IP or hostname
    int port;                 // TCP port
    int weight;               // Configured weight (1..100)
    int effective_weight;     // Dynamic weight for Smooth WRR
    int current_weight;       // Accumulated weight for selection
    int active_conns;         // Current active connections
    int is_alive;             // 1 = Healthy (UP), 0 = Down
    int is_backup;            // 1 = Contingency node
    int is_draining;          // 1 = Draining (no new connections)
    int fail_count;           // Consecutive failures (for circuit breaker)
    int pass_count;           // Consecutive successes (for recovery)
    uint64_t last_check_ms;   // Last health check timestamp
} ArwsBackendNode;

typedef struct {
    char name[64];                              // Pool name (e.g., "api_auth")
    ArwsBackendNode nodes[ARWS_MAX_NODES_PER_POOL]; // Node array
    int node_count;                             // Active nodes in pool
    ArwsLbAlgo algo;                            // Selection algorithm
    int rr_index;                               // Round-robin cursor
    ar_mutex_t lock;                            // Pool-level mutex
    int health_interval_ms;                     // Health check interval
    int health_timeout_ms;                      // Health probe timeout
    int health_fall;                            // Failures before DOWN
    int health_rise;                            // Successes before UP
} ArwsUpstreamPool;
```

#### Functions

| Signature | Description |
|---|---|
| `void arws_upstream_init(void)` | Initialize global pool registry |
| `void arws_upstream_cleanup(void)` | Destroy all pools and free resources |
| `int arws_upstream_create_pool(const char *name, ArwsLbAlgo algo)` | Create a new upstream pool with the given algorithm |
| `void arws_upstream_set_health_params(ArwsUpstreamPool *pool, int interval_ms, int timeout_ms, int fall, int rise)` | Configure health check parameters for a pool |
| `int arws_upstream_add_node(const char *pool_name, const char *host, int port, int weight, int is_backup)` | Add a backend node to a pool |
| `int arws_upstream_remove_node(const char *pool_name, const char *host, int port)` | Remove a node from a pool |
| `int arws_upstream_set_node_drain(const char *pool_name, const char *host, int port, int drain)` | Set drain mode (1=drain, 0=undrain) |
| `ArwsBackendNode* arws_upstream_select(const char *pool_name, const char *client_ip)` | Select a backend node using the pool's algorithm |
| `void arws_upstream_release(const char *pool_name, ArwsBackendNode *node)` | Release a node (decrement active_conns) |
| `ArwsUpstreamPool* arws_upstream_get_pool(const char *name)` | Lookup pool by name |
| `int arws_upstream_get_all_pools(ArwsUpstreamPool **out, int max)` | Get array of all pools |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `ARWS_MAX_NODES_PER_POOL` | `32` | Maximum nodes per upstream pool |
| `ARWS_MAX_POOLS` | `64` | Maximum upstream pools |

---

### 4.9 Health Check Monitor

**Files**: `arws_health.c`, `arws_health.h`

**Purpose**: Asynchronous background thread that continuously probes all upstream nodes with non-blocking TCP connections. Uses configurable fall/rise thresholds to transition nodes between UP and DOWN states.

#### Functions

| Signature | Description |
|---|---|
| `int arws_health_start(void)` | Start the health monitoring thread. Returns 0 on success |
| `void arws_health_stop(void)` | Signal the monitoring thread to stop and join |

#### Internal Functions (static)

| Function | Description |
|---|---|
| `health_check_worker(void *arg)` | Main loop: iterates all pools/nodes, calls `probe_tcp_node`, updates `is_alive` based on fall/rise |
| `probe_tcp_node(const char *host, int port, int timeout_ms)` | Non-blocking TCP connect with `select()` timeout. Returns 1=reachable, 0=failed |

---

### 4.10 Router & Extended Router

**Files**: `router.c`, `router.h`, `router_ex.c`

**Purpose**: Two-tier routing system. `router.c` provides the basic hash-table router for local handlers. `router_ex.c` provides the extended router supporting proxy routes, stream routes, redirect routes, wildcard matching (`/*`), host-based virtual routing, and priority ordering by path specificity.

#### Functions (router.c)

| Signature | Description |
|---|---|
| `void add_route(const char *path, const char *method, const char *domain, RequestHandler handler)` | Register a local handler for path/method/domain |
| `void router_dispatch(ClientConnection *conn, HttpRequest *req)` | Dispatch incoming request to the best matching handler |

#### Functions (router_ex.c)

| Signature | Description |
|---|---|
| `void arws_route_init(void)` | Initialize extended route table |
| `int arws_add_route(const char *host, const char *path, const char *method, int backend_id, const char *mode)` | Register a backend route |
| `int arws_add_proxy_route(const char *host, const char *path, const char *target_url)` | Register a reverse proxy route |
| `int arws_add_stream_route(const char *host, const char *path, const char *target_url)` | Register a stream proxy route |
| `int arws_add_redirect_route(const char *host, const char *path, const char *target_url)` | Register a redirect route |
| `int arws_add_handler(const char *host, const char *path, const char *method, RequestHandler handler)` | Register a local function handler |
| `int arws_remove_route(const char *host, const char *path, const char *method)` | Remove a specific route |
| `int arws_remove_routes_by_backend(int backend_id)` | Remove all routes associated with a backend |
| `ArwsRoute* arws_route_match(const char *host, const char *path, const char *method)` | Find best matching route (prefers exact path > wildcard, specific host > wildcard host) |

---

### 4.11 Operational Modes & Config

**Files**: `modes.c`, `modes.h`, `arws_config.c`, `arws_config.h`

**Purpose**: Operational mode engine (`production` / `test` / `maintenance`) with per-route overrides, maintenance IP whitelist, hot-reload config watchdog, and proxy/stream route management.

#### Enums

```c
typedef enum {
    ARWS_MODE_TEST       = 0,
    ARWS_MODE_PRODUCTION = 1
} ArwsMode;
```

#### Functions (arws_config)

| Signature | Description |
|---|---|
| `int arws_config_load(const char *path)` | Load and parse arws.cfg |
| `const char* arws_config_get_path(void)` | Get resolved config file path |
| `int arws_config_reload_from_disk(void)` | Hot-reload config without downtime |
| `void arws_config_watchdog_stop(void)` | Stop the file watcher thread |
| `const char* arws_config_get_effective_mode(const char *host, const char *path, const char *client_ip)` | Resolve effective mode (considers overrides, maintenance IPs, global mode) |
| `int arws_config_is_maintenance_ip(const char *client_ip)` | Check if IP is whitelisted for maintenance bypass |
| `int arws_config_add_override(const char *host, const char *path, const char *mode)` | Add mode override for host/path |
| `int arws_config_remove_override(const char *host, const char *path)` | Remove mode override |
| `int arws_config_set_global(const char *mode)` | Set global operational mode |
| `const char* arws_config_get_global_mode(void)` | Get current global mode string |
| `int arws_config_get_cache_ttl(void)` | Get configured cache TTL |
| `int arws_config_set_cache_ttl(int seconds)` | Set cache TTL |
| `int arws_config_is_no_cache(const char *host, const char *path)` | Check if route has `no-cache` flag |
| `int arws_config_add_proxy_route(const char *host, const char *path, const char *target_url)` | Register proxy route from config |
| `int arws_config_add_stream_route(const char *host, const char *path, const char *target_url)` | Register stream route from config |
| `int arws_config_dump_routes(char *out, int size)` | Dump all registered routes to string buffer |

#### Functions (modes)

| Signature | Description |
|---|---|
| `void modes_init(void)` | Initialize mode engine |
| `const char* modes_get_effective(const char *host, const char *path)` | Get effective mode for host/path |
| `int modes_set_global(const char *mode)` | Set global mode |
| `const char* modes_get_global(void)` | Get global mode string |

#### Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_OVERRIDES` | `128` | Maximum per-route mode overrides |
| `MAX_MAINTENANCE_IPS` | `32` | Maximum maintenance whitelist IPs |
| `CONFIG_POLL_MS` | `2000` | Config file poll interval (2 seconds) |
| `MAX_LINE` | `512` | Maximum line length in config file |

---

### 4.12 Dispatcher

**File**: `dispatcher.c`

**Purpose**: Central request dispatcher that routes incoming requests to the appropriate handler based on route matching results. Handles cache lookup/store, upstream pool selection, stream proxy forwarding, redirects, and local handler execution.

The dispatcher returns an integer result code:
- **0**: Request handled via IPC/proxy/upstream
- **1**: HTTP Redirect (301/302)
- **2**: Local handler function executed

---

### 4.13 IPC Control Plane

**Files**: `ipc/ipc_pipe.c`, `ipc/ipc.h`

**Purpose**: Binary framing protocol for inter-process communication between ARWS and arcore/applications. Used for service registration, route injection, health queries, cache management, and backend query routing.

#### Structs

```c
typedef struct {
    int type;              // Message type (opcode)
    int length;            // Payload length in bytes
    unsigned char *data;   // Payload buffer (heap-allocated)
} IpcFrame;
```

#### Functions

| Signature | Description |
|---|---|
| `int ipc_send_frame(int fd, int type, const unsigned char *data, int length)` | Send a framed IPC message: `[4B length BE][1B type][payload]` |
| `int ipc_recv_frame(int fd, IpcFrame *frame)` | Receive and decode an IPC frame |
| `void ipc_free_frame(IpcFrame *frame)` | Free heap-allocated frame payload |
| `int ipc_send_raw(int fd, const unsigned char *data, int length)` | Send raw bytes (no framing) |
| `int ipc_recv_raw(int fd, unsigned char *buf, int maxlen)` | Receive raw bytes (no framing) |

#### Opcodes

| Opcode | Constant | Description |
|---|---|---|
| `1` | `IPC_REGISTER` | Register a backend and its routes |
| `2` | `IPC_UNREGISTER` | Unregister a backend |
| `3` | `IPC_REQUEST` | Forward a request to a backend |
| `4` | `IPC_RESPONSE` | Response from a backend |
| `5` | `IPC_HEARTBEAT` | Keep-alive ping |
| `6` | `IPC_ACK` | Acknowledge receipt |
| `7` | `IPC_ERROR` | Error response |

---

### 4.14 Legacy BEMF & API Plugin

**Files**: `bemf.c`, `bemf.h`, `api.c`, `api.h`

**Purpose**: Legacy embedded web server module for static pages and internal administrative APIs.

#### Functions

| Signature | Description |
|---|---|
| `int bemf_entry(void)` | Initialize and start the BEMF webserver |
| `void api_plugin_init(void)` | Initialize the API plugin route table |
| `void api_plugin_handler(ClientConnection *conn, HttpRequest *req)` | Dispatch request to API plugin handler |
| `void api_add_route(const char *path, const char *method, RouteHandler handler)` | Register an API route handler |
| `void send_page(ClientConnection *conn, const char *folder_name, const char *request_path)` | Serve static page from disk |

---

### 4.15 Utilities & HTTP Responses

**Files**: `arws_utils.c`, `arws_utils.h`

**Purpose**: Standardized HTTP response helpers and utility functions.

#### Response Functions

| Function | Status Code | Description |
|---|---|---|
| `arws_sendpage(conn, html)` | 200 | Send raw HTML page |
| `arws_send_200(conn, body)` | 200 | Send 200 OK with body |
| `arws_send_201(conn, body)` | 201 | Send 201 Created |
| `arws_send_204(conn)` | 204 | Send 204 No Content |
| `arws_send_301(conn, url)` | 301 | Permanent redirect |
| `arws_send_302(conn, url)` | 302 | Temporary redirect |
| `arws_send_400(conn, msg)` | 400 | Bad Request |
| `arws_send_401(conn, msg)` | 401 | Unauthorized |
| `arws_send_403(conn, msg)` | 403 | Forbidden |
| `arws_send_404(conn)` | 404 | Not Found (embedded HTML template) |
| `arws_send_429(conn, msg)` | 429 | Too Many Requests |
| `arws_send_500(conn, msg)` | 500 | Internal Server Error |
| `arws_send_501(conn, msg)` | 501 | Not Implemented |
| `arws_send_502(conn, msg)` | 502 | Bad Gateway |
| `arws_send_503(conn, msg)` | 503 | Service Unavailable |
| `arws_send_maintenance(conn)` | 503 | Maintenance page (embedded HTML) |
| `arws_send_json(conn, status, json)` | any | Send JSON response with proper Content-Type |
| `arws_send_error(conn, status, msg)` | any | Send JSON error: `{"error": "msg"}` |
| `arws_serve_file(conn, path, type)` | 200 | Serve file from disk |

---

## 5. IPC Protocol Specification

### Frame Layout

```
┌───────────────────┬─────────────────┬──────────────────────────┐
│ 4 Bytes           │ 1 Byte          │ N Bytes                  │
│ Payload Length     │ Message Type    │ Payload                  │
│ (Big-Endian u32)  │ (Opcode)        │ (JSON / String / Binary) │
└───────────────────┴─────────────────┴──────────────────────────┘
```

### Admin Commands via Port 9500

| Command | Payload | Response |
|---|---|---|
| `ping` | (none) | `pong` |
| `status` | (none) | JSON with mode, port, bind, global_mode |
| `routes` | (none) | Formatted dump of all registered routes |
| `cfg reload` | (none) | Reloads `arws.cfg` from disk |
| `production` / `test` / `maintenance` | (none) | Sets global operational mode |
| `<mode> <host> [path]` | mode + host + optional path | Sets per-route mode override |
| `upstream list` | (none) | Lists all pools with nodes, weights, health, conns |
| `upstream add <pool> <host> <port> [weight] [backup]` | params | Adds node to pool |
| `upstream drain <pool> <host> <port> [1\|0]` | params | Toggles drain mode on a node |

### Backend Registration Frame

When an app registers via IPC, it sends an `IPC_REGISTER` (1) frame with payload:

```
<name> <prefix> <method> <host> <mode> [proxy=<url>] [type=proxy|stream|redirect] [redirect=<url>] [rl=<max>,<window>]
```

---

## 6. Security Model

### 6.1 Anti-Directory Traversal & Path Injection

- `server_path_safe()` blocks: `..`, `%2e`, `%2f`, `%5c`, backslashes `\`, ASCII control characters (<0x20, 0x7F)
- Null byte injection: `%00` is detected and triggers `400 Bad Request`
- Double URL encoding: `url_decode()` is applied twice to catch encoded traversal

### 6.2 Rate Limiting & DoS Protection

- **Global tier**: 5,000 requests / 60 seconds per IP (`ARWS_RL_DEFAULT_MAX`)
- **Custom tier**: Per-route rules injected by apps via IPC (e.g., login: 5 req/60s)
- **Temporary IP blocking**: `arws_ratelimit_block_ip()` with configurable duration

### 6.3 Trusted Proxy Validation

- `X-Forwarded-For` and `CF-Connecting-IP` are only trusted if the peer IP matches a CIDR in `ARWS_TRUSTED_PROXY`
- Strict `inet_pton` validation on all IP addresses
- Cloudflare support via `BEHIND_CLOUDFLARE=1`

### 6.4 Cache Poisoning Prevention

Responses containing `Set-Cookie` are never cached (`response_has_set_cookie` check in cache storage path).

### 6.5 Session Security

- Tokens generated with `RAND_bytes()` (CSPRNG, 256-bit entropy)
- Token comparison uses constant-time `ct_compare()` — immune to timing side-channel attacks
- Anonymous tracking cookie `ARC_ANON_ID` uses `HttpOnly; SameSite=Lax; Secure` flags

### 6.6 TLS 1.3

- OpenSSL-based TLS termination on port 443
- Automatic HTTP→HTTPS redirect via dedicated thread on port 80
- Certificate path: `arcore/storage/arws/certs/cert.pem` and `key.pem`

---

## 7. Operational Guide & CLI Reference

### Start / Stop

```bash
# Boot full ecosystem (ARWS starts automatically as service)
alrios power on

# Stop everything
alrios power off

# Hot-reload packages and routes
alrios power reload
```

### ARWS Gateway Commands

```bash
# Check gateway status (mode, port, bind, connections)
alrios arws status

# List all registered proxy/stream/backend routes
alrios arws routes

# Reload arws.cfg without restart
alrios arws cfg reload

# Switch global mode
alrios arws global production
alrios arws global test
alrios arws global maintenance

# Per-route mode override
alrios arws override myapp.example.com /api/* production

# Upstream pool management
alrios arws upstream list
alrios arws upstream add api_pool 10.0.0.1 8080 5 0   # weight=5, backup=0
alrios arws upstream add api_pool 10.0.0.2 8080 1 1   # backup node
alrios arws upstream drain api_pool 10.0.0.1 8080 1    # start draining
alrios arws upstream drain api_pool 10.0.0.1 8080 0    # stop draining
```

### Maintenance Scenario

```bash
# 1. Add your admin IP to whitelist in arws.cfg:
#    maintenance_ips=["203.0.113.10"]
#
# 2. Switch to maintenance mode:
alrios arws global maintenance

# 3. Only 203.0.113.10 can access the site; everyone else sees 503 maintenance page
# 4. When done:
alrios arws global production
```

---

## 8. Build & Packaging

### Compilation

ARWS compiles as a **shared library** (`libarws.arlib`) loaded dynamically by arcore:

```bash
gcc -shared -fPIC -O2 \
  -Isrc -I../../ALRIOS/core \
  -I../../ALRIOS/arkernel/include \
  -I../../ALRIOS/arkernel/ipc \
  -I../../ALRIOS/arkernel/os/include \
  -o $STAGING/libarws.arlib \
  src/arws_entry.c src/arws_gateway.c src/arws_utils.c \
  src/arws_config.c src/arws_ratelimit.c src/arws_session.c \
  src/arws_cache.c src/arws_proxy.c src/arws_stream_proxy.c \
  src/arws_upstream.c src/arws_health.c src/modes.c \
  src/router_ex.c src/registry.c src/dispatcher.c \
  src/server.c src/cJSON.c \
  -L$ARCORE/lib -larkernel -lssl -lcrypto -lpthread
```

### Dependencies

| Library | Purpose |
|---|---|
| `libarkernel.a` | ALRIOS HAL (process, socket, threads, sync) |
| `libssl` / `libcrypto` | OpenSSL for TLS termination and CSPRNG |
| `libpthread` | POSIX threading |

### .arapp Manifest (`arws.arappmake`)

```json
{
  "name": "arws",
  "version": "0.2.01",
  "runtime": "native",
  "entry": "libarws.arlib",
  "services": [{"name": "arws", "entry": "arws_entry"}],
  "files": ["libarws.arlib", "src/web/404/index.html", "src/web/maintenance/index.html"],
  "commands": ["routes", "status", "cfg reload", "upstream list", "maintenance", "ping"]
}
```

---

*Document generated from source code analysis of ARWS v0.2.01.*
*Engineered by ALRI Development. Governed by ALRI GROUP © 2026 — All rights reserved.*
*License: ARGLP (ALRI GROUP LICENSE PERMISSIVE — Version 2)*
