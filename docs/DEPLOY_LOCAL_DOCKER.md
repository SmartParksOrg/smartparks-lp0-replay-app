# Local Deployment (Docker Desktop)

This guide works on Windows and macOS with Docker Desktop installed.
Node.js is included in the container to support JavaScript decoders.

## 1) Build and run

```bash
docker compose up -d --build
```

### Optional: one-click launcher (no terminal)

- Windows: double-click `scripts/run_docker_windows.bat`
- macOS: double-click `scripts/run_docker_macos.command`
  - If macOS blocks it, right-click → Open, or run:
    ```bash
    chmod +x scripts/run_docker_macos.command
    ```
- To stop the app:
  - Windows: `scripts/stop_docker_windows.bat`
  - macOS: `scripts/stop_docker_macos.command` (run once: `chmod +x scripts/stop_docker_macos.command`)
- To check status:
  - Windows: `scripts/status_docker_windows.bat`
  - macOS: `scripts/status_docker_macos.command` (run once: `chmod +x scripts/status_docker_macos.command`)

## 2) Open the app

Browse to:

```
http://localhost:18080
```

## 3) Data location

App data is stored in `./data` on your machine.
