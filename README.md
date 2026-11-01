# ai-app-security-gateway

A FastAPI security gateway that sits between client apps and LLM providers (OpenAI first).
It inspects prompts and responses for prompt injection, jailbreaks, PII leakage and
system-prompt leakage, and traces every decision to Langfuse.

> Work in progress: built step by step. See `docs/learning-notes/` for the write-up of each step.

## Status
- [x] Step 1: Input guardrails: PII masker + prompt-injection detector
- [x] Step 2: Output inspector: secret redaction, canary tokens, system prompt overlap
- [ ] Step 3: Core config, error payloads, logging
- [ ] Step 4: OpenAI client + Langfuse telemetry
- [ ] Step 5: `/v1/chat/completions` proxy + `/health`
- [ ] Step 6: Docker + docker-compose
- [ ] Step 7: Integration tests
- [ ] Step 8: pre-commit (ruff + gitleaks) and GitHub Actions CI

## Quick start
```bash
poetry env use python3.12
poetry install
poetry run pytest -v
```

`requirements.txt` is generated from `poetry.lock` (`poetry export`). Don't edit it by hand.
