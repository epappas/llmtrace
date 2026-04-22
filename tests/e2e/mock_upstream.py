"""Canned in-process FastAPI upstream used by the e2e harness in PR-gate mode.

Implements just enough of the OpenAI Chat Completions surface for the
LLMTrace proxy to forward requests successfully and observe a 200
response. The mock is intentionally dumb — it always returns the same
canned assistant message regardless of the inbound prompt — because the
PR-gate test surface only asserts on what LLMTrace decides about the
request, not on upstream content. The real-LLM upstream lives in the
nightly job (Loop E2E-L10).

The mock is started by `tests/e2e/conftest.py::mock_upstream` as an
in-process subprocess, so it shares no module state with the test
runner.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def _canned_chat_completion(model: str) -> dict:
    """Return a deterministic OpenAI-shaped response."""
    now = int(time.time())
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": now,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        "This is a canned mock-upstream response used by the "
                        "LLMTrace e2e harness. The mock does not interpret "
                        "the inbound prompt."
                    ),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 32,
            "completion_tokens": 32,
            "total_tokens": 64,
        },
    }


def build_app() -> FastAPI:
    app = FastAPI(title="LLMTrace e2e mock upstream", version="0.1.0")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        model = body.get("model", "mock-model")
        return JSONResponse(_canned_chat_completion(model))

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log-level", default="warning")
    args = parser.parse_args(argv)

    uvicorn.run(
        build_app(),
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
