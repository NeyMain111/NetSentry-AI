from __future__ import annotations

import argparse
import os


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the NetSentry AI local dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--demo", action="store_true", help="Start synthetic demo traffic automatically")
    parser.add_argument("--reload", action="store_true", help="Enable development auto-reload")
    args = parser.parse_args()
    if args.demo:
        os.environ["NETSENTRY_AUTO_DEMO"] = "1"

    import uvicorn

    uvicorn.run("netsentry.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()

