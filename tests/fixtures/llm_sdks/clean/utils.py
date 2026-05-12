"""Synthetic fixture: ordinary code, no LLM SDK imports."""
import json
import os


def load_config(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def env_or_default(name: str, default: str) -> str:
    return os.environ.get(name, default)
