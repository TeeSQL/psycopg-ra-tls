# psycopg-ra-tls

psycopg3 driver with RA-TLS attestation verification for dstack TEE databases.

Connect to a TEESQL or dstack-hosted Postgres instance with automatic TDX attestation verification on every connection. Python equivalent of [prisma-ra-tls](https://github.com/AcaciaSystems/prisma-ra-tls).

## Install

```bash
pip install psycopg-ra-tls
```

## Usage

### Production (cluster secret authentication)

Use cluster secret-based authentication with the teesql sidecar. Use `teesql_read` 
or `teesql_readwrite` as the username and your cluster secret as the password.

```python
from psycopg_ratls import connect
from ra_tls_verify import IntelApiVerifier

verifier = IntelApiVerifier(api_key="your-ita-key")

# Use teesql_readwrite as username, cluster secret as password
conn = connect(
    "postgresql://teesql_readwrite:your-32-byte-hex-secret@teesql-host:5433/mydb", 
    verifier=verifier
)

rows = conn.execute("SELECT * FROM users").fetchall()
```

### Development (skip attestation)

```python
from psycopg_ratls import connect
from ra_tls_verify import NoopVerifier

# Use test cluster secret for development
conn = connect(
    "postgresql://teesql_readwrite:test-secret-hex-string@localhost:5433/mydb",
    verifier=NoopVerifier(), 
    allow_simulator=True
)
```

### With MRTD allowlist

```python
from ra_tls_verify import IntelApiVerifier, VerifyOptions

verifier = IntelApiVerifier()
options = VerifyOptions(allowed_mr_td=["abc123..."])

conn = connect("postgresql://postgres@teesql-host:5433/mydb",
               verifier=verifier, options=options)
```

### Async

```python
from psycopg_ratls import connect_async
from ra_tls_verify import IntelApiVerifier

verifier = IntelApiVerifier()
conn = await connect_async(
    "postgresql://teesql_read:your-32-byte-hex-secret@teesql-host:5433/mydb",
    verifier=verifier
)
```

### Backward compatibility

If your DSN already contains a password it is passed through unchanged, so
existing code continues to work without modification.

```python
# Also works — password is forwarded as-is (proxy still replaces it)
conn = connect("postgresql://postgres:anypassword@teesql-host:5433/mydb",
               verifier=verifier)
```

## Migrating from plain psycopg3

**hivemind-core / direct psycopg pattern:**

```python
# Before: direct psycopg with password in DSN
import psycopg
from psycopg.rows import dict_row

self._conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
```

```python
# After: RA-TLS verified, no password required
from psycopg_ratls import connect
from ra_tls_verify import NoopVerifier  # or IntelApiVerifier for production

self._conn = connect(
    "postgresql://postgres@teesql:5433/hivemind",
    verifier=NoopVerifier(),
    allow_simulator=True,   # set False in production with real TDX hardware
)
```

## How it works

1. Adds cluster secret and permission parameters to the PostgreSQL connection URL
2. Connects to Postgres over TLS using psycopg3
3. Extracts the TDX attestation quote from the server's RA-TLS certificate (OID 1.3.6.1.4.1.62397.1.8)
4. Verifies the quote using Intel Trust Authority (or NoopVerifier for dev)
5. Refuses the connection if verification fails

The teesql sidecar proxy intercepts the PostgreSQL startup message after the RA-TLS handshake,
extracts the cluster secret and permission parameters, validates them against the configured
cluster secrets, and authenticates to PostgreSQL using the appropriate shared user account
(teesql_read or teesql_readwrite).

The server proves it is running inside a genuine TEE on every connection, not just at deploy time.
Authentication is based on possession of cluster secrets rather than traditional credentials.

## License

Apache-2.0
