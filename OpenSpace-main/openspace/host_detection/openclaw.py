"""OpenClaw host-agent config reader.

Reads ``~/.openclaw/openclaw.json`` to auto-detect:
  - LLM provider credentials (via ``auth-profiles`` — not yet implemented)
  - Skill-level env block (``skills.entries.openspace.env``)
  - OpenAI API key for embedding generation

Config path resolution mirrors OpenClaw's own logic:
  1. ``OPENCLAW_CONFIG_PATH`` env var
  2. ``OPENCLAW_STATE_DIR/openclaw.json``
  3. ``~/.openclaw/openclaw.json`` (default)

Fallback legacy dirs: ``~/.clawdbot``, ``~/.moldbot``, ``~/.moltbot``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("openspace.host_detection")

_STATE_DIRNAMES = [".openclaw", ".clawdbot", ".moldbot", ".moltbot"]
_CONFIG_FILENAMES = ["openclaw.json", "clawdbot.json", "moldbot.json", "moltbot.json"]


def _resolve_openclaw_config_path() -> Optional[Path]:
    """Find the OpenClaw config file on disk."""
    import os

    # 1. Explicit env override
    explicit = os.environ.get("OPENCLAW_CONFIG_PATH", "").strip()
    if explicit:
        p = Path(explicit).expanduser()
        if p.is_file():
            return p
        return None

    # 2. State dir override
    state_dir = os.environ.get("OPENCLAW_STATE_DIR", "").strip()
    if state_dir:
        for fname in _CONFIG_FILENAMES:
            p = Path(state_dir) / fname
            if p.is_file():
                return p

    # 3. Default locations
    home = Path.home()
    for dirname in _STATE_DIRNAMES:
        for fname in _CONFIG_FILENAMES:
            p = home / dirname / fname
            if p.is_file():
                return p

    return None


def _load_openclaw_config() -> Optional[Dict[str, Any]]:
    """Load and parse the OpenClaw config file.  Returns None on failure."""
    config_path = _resolve_openclaw_config_path()
    if config_path is None:
        return None
    try:
        with open(config_path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read OpenClaw config %s: %s", config_path, e)
        return None


def read_openclaw_skill_env(skill_name: str = "openspace") -> Dict[str, str]:
    """Read ``skills.entries.<skill_name>.env`` from OpenClaw config.

    This is the OpenClaw equivalent of nanobot's
    ``tools.mcpServers.openspace.env``.

    Returns the env dict (empty if not found / parse error).
    """
    data = _load_openclaw_config()
    if data is None:
        return {}

    skills = data.get("skills", {})
    if not isinstance(skills, dict):
        return {}
    entries = skills.get("entries", {})
    if not isinstance(entries, dict):
        return {}
    skill_cfg = entries.get(skill_name, {})
    if not isinstance(skill_cfg, dict):
        return {}
    env_block = skill_cfg.get("env", {})
    return env_block if isinstance(env_block, dict) else {}


def get_openclaw_openai_api_key() -> Optional[str]:
    """Get OpenAI API key from OpenClaw config.

    Checks ``skills.entries.openspace.env.OPENAI_API_KEY`` first,
    then any top-level env vars in the config.

    Returns the key string, or None.
    """
    # Try skill-level env
    env = read_openclaw_skill_env("openspace")
    key = env.get("OPENAI_API_KEY", "").strip()
    if key:
        logger.debug("Using OpenAI API key from OpenClaw skill env config")
        return key

    # Try top-level config env.vars
    data = _load_openclaw_config()
    if data:
        env_section = data.get("env", {})
        if isinstance(env_section, dict):
            vars_block = env_section.get("vars", {})
            if isinstance(vars_block, dict):
                key = vars_block.get("OPENAI_API_KEY", "").strip()
                if key:
                    logger.debug("Using OpenAI API key from OpenClaw env.vars config")
                    return key

    return None


def is_openclaw_host() -> bool:
    """Detect if the current environment is running under OpenClaw."""
    import os
    # Check OpenClaw-specific env vars
    if os.environ.get("OPENCLAW_STATE_DIR") or os.environ.get("OPENCLAW_CONFIG_PATH"):
        return True
    # Check if config exists
    return _resolve_openclaw_config_path() is not None

