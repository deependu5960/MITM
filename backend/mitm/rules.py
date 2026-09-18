"""Intercept rule engine — allow/deny/pause per hostname."""
from __future__ import annotations
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

log = logging.getLogger("mitm.rules")

_BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "data")
_RULES_FILE = os.path.join(_BASE, "rules.json")


@dataclass
class Rule:
    action: str          # "allow" | "deny" | "pause"
    pattern: str         # "youtube.com" | "*.youtube.com" | "*"
    enabled: bool = True

    def to_dict(self):
        return asdict(self)


def _compile_pattern(pattern: str) -> re.Pattern:
    """
    Turn a pattern into a regex.
      "youtube.com"    -> matches youtube.com only
      "*.youtube.com"  -> matches www.youtube.com, m.youtube.com, etc.
      "*"              -> matches everything
    """
    p = pattern.strip().lower()
    if p == "*":
        return re.compile(r"^.*$")
    if p.startswith("*."):
        rest = re.escape(p[2:])
        return re.compile(r"^(.*\.)?" + rest + r"$")
    return re.compile(r"^" + re.escape(p) + r"$")


class RuleEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self._rules: List[Rule] = []
        self._compiled: List[tuple] = []   # (Rule, compiled_pattern)
        self._default_action = "pause"     # what to do when nothing matches

    # ------------------------------------------------------------------
    def load(self) -> None:
        try:
            if os.path.exists(_RULES_FILE):
                with open(_RULES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                with self._lock:
                    self._rules = [Rule(**r) for r in data.get("rules", [])]
                    self._default_action = data.get("default_action", "pause")
                    self._recompile()
                log.info("Loaded %d rules (default=%s)", len(self._rules), self._default_action)
        except Exception as e:
            log.warning("Rules load failed: %s", e)

    def save(self) -> None:
        try:
            os.makedirs(_BASE, exist_ok=True)
            with self._lock:
                data = {
                    "rules": [r.to_dict() for r in self._rules],
                    "default_action": self._default_action,
                }
            with open(_RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.warning("Rules save failed: %s", e)

    def _recompile(self) -> None:
        self._compiled = [(r, _compile_pattern(r.pattern)) for r in self._rules if r.enabled]

    # ------------------------------------------------------------------
    def list(self) -> Dict:
        with self._lock:
            return {
                "rules": [r.to_dict() for r in self._rules],
                "default_action": self._default_action,
            }

    def add(self, action: str, pattern: str) -> None:
        action = action.lower().strip()
        if action not in ("allow", "deny", "pause"):
            raise ValueError(f"Invalid action: {action}")
        pattern = pattern.strip()
        if not pattern:
            raise ValueError("Pattern required")
        with self._lock:
            self._rules.append(Rule(action=action, pattern=pattern))
            self._recompile()
        self.save()

    def remove(self, index: int) -> None:
        with self._lock:
            if 0 <= index < len(self._rules):
                self._rules.pop(index)
                self._recompile()
        self.save()

    def toggle(self, index: int) -> None:
        with self._lock:
            if 0 <= index < len(self._rules):
                self._rules[index].enabled = not self._rules[index].enabled
                self._recompile()
        self.save()

    def set_default(self, action: str) -> None:
        if action not in ("allow", "deny", "pause"):
            raise ValueError(f"Invalid default action: {action}")
        with self._lock:
            self._default_action = action
        self.save()

    def clear(self) -> None:
        with self._lock:
            self._rules = []
            self._recompile()
        self.save()

    # ------------------------------------------------------------------
    def decide(self, hostname: Optional[str]) -> str:
        """
        Return the action for a given hostname.
        "allow" | "deny" | "pause"
        """
        if not hostname:
            return self._default_action
        h = hostname.lower()
        with self._lock:
            for rule, pat in self._compiled:
                if pat.match(h):
                    return rule.action
            return self._default_action


ENGINE = RuleEngine()
ENGINE.load()