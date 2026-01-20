# Local Deployment (Docker Desktop)

This guide works on Windows and macOS with Docker Desktop installed.
Node.js is included in the container to support JavaScript decoders.

## 1) Build and run

```bash
docker compose up -d --build
```

## 2) Open the app

Browse to:

```
http://localhost:18080
```

## 3) Data location

App data is stored in `./data` on your machine.
