# ARWS Gateway & L7 Load Balancer (`arws.arapp`)

**ALRI Web Services Gateway** — High-performance HTTP/HTTPS Reverse Proxy, API Gateway, and Layer 7 Load Balancer for Enterprise & Government Infrastructure.

---

## ⚙️ Key Architecture & Features

- **Port Binding**: Port 80 (HTTP / Test) and 443 (HTTPS / TLS 1.3 Production).
- **High Concurrency**: Up to 65,536 concurrent TCP connections via non-blocking I/O.
- **Layer 7 Load Balancing**:
  - Dynamic **Upstream Pools** (`@pool_name`) supporting up to 32 nodes per pool and 64 active pools.
  - **Smooth Weighted Round-Robin (WRR)** (Nginx-grade smooth traffic distribution).
  - **Least Connections** (routes to backends with lowest active TCP connections).
  - **IP Consistent Hashing** (sticky sessions based on client IP hash).
  - **Contingency / Backup Nodes**: Automatic failover to standby backends if all primary nodes fail.
  - **Graceful Draining (DRAIN)**: Allows maintenance of individual nodes without dropping active client connections.
- **Resilience & Health Monitoring**:
  - **Active Health Prober**: Dedicated asynchronous background thread probing nodes (`probe_tcp_node`) with configurable intervals, timeouts, and fall/rise thresholds.
  - **Passive Circuit Breaker**: Immediate detection of 500/502/503/504 errors and timeouts, automatically reducing node weight and marking failed nodes `DOWN`.
- **Caching**: 16-shard in-memory LRU cache with configurable TTL.
- **Rate Limiting**: Automatic IP-based token bucket rate limiting (`HTTP 429 Too Many Requests`).
- **Zero-Trust Security**: Header sanitization, trusted proxy CIDR verification (`ARWS_TRUSTED_PROXY`), and strict out-of-process isolation.

---

## 🛠️ CLI Operations (`alrios arws`)

Manage upstream pools and inspect gateway metrics directly in real-time via the ALRIOS IPC channel (port 9500):

```bash
# 1. Inspect Gateway Runtime Status
alrios arws status

# 2. List all Upstream Pools, Node Health (UP/DOWN), Connections & Stats
alrios arws upstream list

# 3. Add Backends to a Pool
# Syntax: alrios arws upstream add <pool_name> <host> <port> [weight=1..100] [backup=0|1]
alrios arws upstream add api_auth 10.0.0.1 8080 5 0   # Primary node with weight 5
alrios arws upstream add api_auth 10.0.0.2 8080 1 0   # Primary node with weight 1
alrios arws upstream add api_auth 10.0.0.99 8080 1 1  # Backup node in cold standby

# 4. Graceful Draining for Maintenance
# Syntax: alrios arws upstream drain <pool_name> <host> <port> [1=drain | 0=undrain]
alrios arws upstream drain api_auth 10.0.0.1 8080 1

# 5. Reload Gateway Configuration
alrios arws cfg reload
```

---

## 📁 Source Code Components

| File | Purpose |
| :--- | :--- |
| `src/apps/arws/arws_upstream.c` / `.h` | Upstream Pool Engine, Smooth WRR, Least Conn, IP Hash & Circuit Breaker. |
| `src/apps/arws/arws_health.c` / `.h` | Asynchronous Active Health Prober & Recovery Thread. |
| `src/apps/arws/dispatcher.c` | L7 Request Dispatcher with `@pool_name` dynamic routing. |
| `src/apps/arws/arws_gateway.c` | Admin IPC Server (Port 9500) & CLI command handler. |
| `src/apps/arws/server.c` | Non-blocking Core HTTP/TLS Socket Server. |
