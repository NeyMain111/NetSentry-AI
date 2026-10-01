#!/usr/bin/env bash

cd /home/kaliksuleyman/project/NetSentry_AI || exit 1

export NETSENTRY_USE_OLLAMA=1
export NETSENTRY_OLLAMA_MODEL=qwen2.5:3b
unset NETSENTRY_AUTO_DEMO

exec .venv/bin/netsentry
