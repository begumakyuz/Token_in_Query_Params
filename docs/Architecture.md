# 🏛️ System Architecture Analysis (L14 Deep Dive)

This document provides a technical breakdown of the multi-layered security architecture designed to mitigate "Token in Query Params" (L14) vulnerabilities.

## 🏗️ Core Components

### 1. Client Layer (Attacker/User)
- **Protocol**: HTTPS (TLS 1.3)
- **Interaction**: Web Browsers, Postman, or `curl`.
- **Primary Vulnerability**: Passing `token=XYZ` in the URI string.

### 2. Network Proxy (Nginx v1.25)
Nginx acts as the "Outer Guardian" and handles:
- **Log Scrubbing**: Using the `map` directive to replace sensitive URI parameters with `***` in `access.log`.
- **Token Stripping**: Intercepting GET parameters and re-injecting them into the `Authorization` header for internal backend consumption.
- **Rate-Limiting**: Protecting against dictionary attacks on tokens.

### 3. Application Core (Flask v3.0)
The Python backend implements "Defense in Depth":
- **HMAC Validation**: Using `hmac.compare_digest` to prevent timing attacks.
- **Middleware**: A hardened request filter that enforces HSTS, CSP, and X-Content-Type headers.
- **Telemetry**: Real-time processed-time headers for auditing logic flows.

### 4. Forensic Engine (Rust v4.0 Parallel)
A high-performance audit tool:
- **Parallel Scanning**: Uses `std::thread` to scan log files concurrently across 4+ CPU cores.
- **Memory Safety**: Rust's ownership model prevents buffer overflows during log parsing.

---

## 🔄 Data Flow Diagram

```mermaid
graph LR
    subgraph "External Network"
    A[Client] -->|GET /vulnerable?token=...| B(Nginx Proxy)
    A[Client] -->|GET /secure (Bearer Header)| B
    end
    
    subgraph "DMZ (Isolated Docker Network)"
    B -->|Scrubbed Logs| C[Forensic Storage]
    B -->|Header Injection| D[Flask Backend]
    end
    
    subgraph "Active Audit"
    E[Rust Generator] -->|Schedules Scan| C
    E -->|Renders Report| F[AUDIT_REPORT.md]
    end
```

## 🔐 Security Principles Implemented
1. **Least Privilege**: The Flask app runs as a rootless `appuser` (UID 1000).
2. **Confidentiality**: Zero Plaintext keys in system logs.
3. **Availability**: Rate-limiting and memory-safe auditing.
4. **Accountability**: Each incident is logged with IP and high-fidelity timestamps.
