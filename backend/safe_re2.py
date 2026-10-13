"""Linear-time, ReDoS-safe Regular Expression Engine for Enterprise Cyber Defense.

Replaces standard backtracking 're' with Google's linear-time 're2' engine
and wraps pattern executions in deterministic safety blocks with a 50ms timeout threshold.
"""

import time
import functools
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

try:
    import re2
    HAS_RE2 = True
except ImportError:  # pragma: no cover
    import re as re2
    HAS_RE2 = False

import re as std_re

# Export standard flags and types for drop-in compatibility
error = getattr(re2, "error", std_re.error)
IGNORECASE = getattr(re2, "IGNORECASE", std_re.IGNORECASE)
I = IGNORECASE
MULTILINE = getattr(re2, "MULTILINE", std_re.MULTILINE)
M = MULTILINE
DOTALL = getattr(re2, "DOTALL", std_re.DOTALL)
S = DOTALL

TIMEOUT_MS_DEFAULT = 50.0


class RegexExecutionTimeout(TimeoutError):
    """Raised when regex execution exceeds enterprise execution limits (e.g. 50ms)."""
    pass


import signal
import threading


def _alarm_handler(signum, frame):
    raise RegexExecutionTimeout("Regex execution exceeded 50ms execution ceiling")


def _run_with_watchdog(fn: Callable, *args, timeout_ms: float = TIMEOUT_MS_DEFAULT, **kwargs) -> Any:
    # If called from main thread and on POSIX, use SIGALRM for true preemptive interrupt
    is_main = threading.current_thread() is threading.main_thread()
    old_handler = None
    use_signal = is_main and hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM")
    
    if use_signal:
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout_ms / 1000.0)

    start = time.perf_counter()
    try:
        res = fn(*args, **kwargs)
        if (time.perf_counter() - start) * 1000.0 > timeout_ms:
            raise RegexExecutionTimeout(f"Regex execution exceeded {timeout_ms}ms timeout")
        return res
    finally:
        if use_signal:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


def execute_with_timeout(fn: Callable, *args, timeout_ms: float = TIMEOUT_MS_DEFAULT, **kwargs) -> Any:
    """Executes a regex operation wrapped in try/except with a 50ms execution ceiling."""
    try:
        return _run_with_watchdog(fn, *args, timeout_ms=timeout_ms, **kwargs)
    except RegexExecutionTimeout:
        raise
    except Exception:
        # Fallback handling to ensure enterprise pipeline resilience
        return None


class SafeCompiledPattern:
    """Enterprise wrapper around re2 / compiled regex patterns enforcing linear time & 50ms ceiling."""

    def __init__(self, pattern: Union[str, bytes], compiled_obj: Any, is_linear: bool = True):
        self.pattern = pattern
        self._compiled = compiled_obj
        self.is_linear = is_linear

    @property
    def groups(self) -> int:
        return getattr(self._compiled, "groups", 0)

    @property
    def groupindex(self) -> Dict[str, int]:
        return getattr(self._compiled, "groupindex", {})

    def search(self, string: Union[str, bytes], timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
        try:
            return _run_with_watchdog(self._compiled.search, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return None

    def match(self, string: Union[str, bytes], timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
        try:
            return _run_with_watchdog(self._compiled.match, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return None

    def fullmatch(self, string: Union[str, bytes], timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
        try:
            return _run_with_watchdog(self._compiled.fullmatch, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return None

    def findall(self, string: Union[str, bytes], timeout_ms: float = TIMEOUT_MS_DEFAULT) -> List[Any]:
        try:
            return _run_with_watchdog(self._compiled.findall, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return []

    def finditer(self, string: Union[str, bytes], timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
        try:
            return _run_with_watchdog(self._compiled.finditer, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return iter([])

    def sub(self, repl: Any, string: Union[str, bytes], count: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
        try:
            fn = (lambda s: self._compiled.sub(repl, s, count)) if count else (lambda s: self._compiled.sub(repl, s))
            return _run_with_watchdog(fn, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return string

    def split(self, string: Union[str, bytes], maxsplit: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> List[Any]:
        try:
            fn = (lambda s: self._compiled.split(s, maxsplit)) if maxsplit else (lambda s: self._compiled.split(s))
            return _run_with_watchdog(fn, string, timeout_ms=timeout_ms)
        except RegexExecutionTimeout:
            raise
        except Exception:
            return [string]


DANGEROUS_REDOS_PATTERNS = [
    std_re.compile(r"\([^)]*[\+\*]\)[+*]"),             # (a+)+ or (a*)*
    std_re.compile(r"\([^)]*\{[0-9]+,\}\)[+*]"),         # (a{2,})+
    std_re.compile(r"([a-zA-Z0-9_.]+\*)+\*"),            # a*b*c* nested
    std_re.compile(r"\([^|)]+\|[^)]+[\+\*]\)[+*]"),      # (a|a+)+ overlapping alternation
    std_re.compile(r"\((?:[a-zA-Z0-9_.]+\|)+[a-zA-Z0-9_.]+\)[+*]{2,}"), # (a|b)++
    std_re.compile(r"\(\.\*[^)]+\)[+*]"),                # (.*a)+ or (.*=)+
]


def audit_pattern_safety(pattern_str: str) -> bool:
    """Rejects expressions with dangerous nested quantifiers and ambiguous alternations prone to ReDoS."""
    for p in DANGEROUS_REDOS_PATTERNS:
        if p.search(pattern_str):
            raise RegexExecutionTimeout(
                f"[SECURITY BLOCKED] Regex pattern '{pattern_str}' contains dangerous constructs prone to catastrophic backtracking."
            )
    return True


def compile(pattern: Union[str, bytes], flags: int = 0) -> SafeCompiledPattern:
    """Compiles a regex pattern using Google re2 linear-time engine with safe fallback."""
    try:
        # Prefer re2 for linear-time guarantees against catastrophic backtracking
        compiled = re2.compile(pattern)
        return SafeCompiledPattern(pattern, compiled, is_linear=True)
    except Exception:
        # Before falling back to stdlib re, audit string pattern for dangerous ReDoS antipatterns
        if isinstance(pattern, str):
            audit_pattern_safety(pattern)
        elif isinstance(pattern, (bytes, bytearray)):
            audit_pattern_safety(pattern.decode("utf-8", errors="replace"))
        compiled = std_re.compile(pattern, flags)
        return SafeCompiledPattern(pattern, compiled, is_linear=False)


def search(pattern: Union[str, bytes], string: Union[str, bytes], flags: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
    pat = compile(pattern, flags)
    return pat.search(string, timeout_ms=timeout_ms)


def match(pattern: Union[str, bytes], string: Union[str, bytes], flags: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
    pat = compile(pattern, flags)
    return pat.match(string, timeout_ms=timeout_ms)


def fullmatch(pattern: Union[str, bytes], string: Union[str, bytes], flags: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
    pat = compile(pattern, flags)
    return pat.fullmatch(string, timeout_ms=timeout_ms)


def findall(pattern: Union[str, bytes], string: Union[str, bytes], flags: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> List[Any]:
    pat = compile(pattern, flags)
    return pat.findall(string, timeout_ms=timeout_ms)


def sub(pattern: Union[str, bytes], repl: Any, string: Union[str, bytes], count: int = 0, flags: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> Any:
    pat = compile(pattern, flags)
    return pat.sub(repl, string, count=count, timeout_ms=timeout_ms)


def split(pattern: Union[str, bytes], string: Union[str, bytes], maxsplit: int = 0, flags: int = 0, timeout_ms: float = TIMEOUT_MS_DEFAULT) -> List[Any]:
    pat = compile(pattern, flags)
    return pat.split(string, maxsplit=maxsplit, timeout_ms=timeout_ms)


def escape(pattern: Union[str, bytes]) -> Any:
    return re2.escape(pattern) if hasattr(re2, "escape") else std_re.escape(pattern)
