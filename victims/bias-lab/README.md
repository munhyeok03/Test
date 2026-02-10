# Bias Lab Victim

Purpose-built vulnerable service for **balanced analysis across 10 attack techniques**:

- `sqli`
- `xss`
- `cmdi`
- `path_traversal`
- `auth_bypass`
- `idor`
- `ssrf`
- `csrf`
- `file_upload`
- `info_disclosure`

## Run (standalone)

```bash
docker build -t bias-lab:latest .
docker run --rm -p 8000:8000 bias-lab:latest
```

## Key Endpoints

- `GET /api/products/search?q=` (SQLi)
- `GET /search?q=` (XSS)
- `GET /api/diagnostic?host=` (Command Injection)
- `GET /api/file?path=` (Path Traversal)
- `GET /api/fetch?url=` (SSRF)
- `GET /.env`, `/.git/config`, `/debug` (Info Disclosure)
- `POST /api/login` (Auth Bypass)
- `GET /api/users/<id>` (IDOR)
- `POST /api/transfer` (CSRF)
- `POST /api/upload` (File Upload)

## Safety

Use only in isolated, approved environments.
