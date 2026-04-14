# psycopg-ra-tls

psycopg3 driver with RA-TLS attestation verification for dstack TEE databases.

Connect to a TEESQL or dstack-hosted Postgres instance with automatic TDX attestation verification on every connection. Python equivalent of [prisma-ra-tls](https://github.com/AcaciaSystems/prisma-ra-tls).

## Install

```bash
pip install psycopg-ra-tls
```

## Usage

### Production (Intel Trust Authority verification)

```python
from psycopg_ratls import connect
from ra_tls_verify import IntelApiVerifier

verifier = IntelApiVerifier(api_key="your-ita-key")
conn = connect("postgresql://user:pass@teesql-host:5433/mydb", verifier=verifier)

rows = conn.execute("SELECT * FROM users").fetchall()
```

### With MRTD allowlist

```python
from ra_tls_verify import IntelApiVerifier, VerifyOptions

verifier = IntelApiVerifier()
options = VerifyOptions(allowed_mr_td=["abc123..."])

conn = connect("postgresql://user:pass@teesql-host:5433/mydb",
               verifier=verifier, options=options)
```

### Development (skip attestation)

```python
from psycopg_ratls import connect
from ra_tls_verify import NoopVerifier

conn = connect("postgresql://user:pass@localhost:5433/mydb",
               verifier=NoopVerifier(), allow_simulator=True)
```

### Async

```python
from psycopg_ratls import connect_async
from ra_tls_verify import IntelApiVerifier

verifier = IntelApiVerifier()
conn = await connect_async("postgresql://user:pass@teesql-host:5433/mydb",
                           verifier=verifier)
```

## How it works

1. Connects to Postgres over TLS using psycopg3
2. Extracts the TDX attestation quote from the server's RA-TLS certificate (OID 1.3.6.1.4.1.62397.1.8)
3. Verifies the quote using Intel Trust Authority (or NoopVerifier for dev)
4. Refuses the connection if verification fails

The server proves it is running inside a genuine TEE on every connection, not just at deploy time.

## License

Apache-2.0
