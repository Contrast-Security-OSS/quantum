#!/usr/bin/env python3
"""
ai_client.py: Centralized AI client with token tracking and cost estimation.

Shells out to the `claude` CLI (Claude Code) in non-interactive print mode, using
whatever Claude access is already logged in to this shell (subscription or API key) -
no separate AWS/Bedrock credentials required.

Provides a single interface for all AI calls with:
- Token usage tracking (input/output)
- Cost estimation and logging
- Pre-task cost approval for expensive operations
- Session-level cost accumulation

Usage:
    from ai_client import AIClient

    client = AIClient()

    # Estimate cost before running
    estimated_cost = client.estimate_cost(num_rules=50, avg_tokens_per_rule=2000)
    if estimated_cost > 1.0:
        print(f"Estimated cost: ${estimated_cost:.2f}")
        # Get approval...

    # Make AI call
    response, usage = client.call(prompt, content)

    # Get session summary
    print(client.get_summary())
"""

import json
import subprocess
import time
import random
import threading
from dataclasses import dataclass, field
from typing import Optional


# Rough per-1M-token pricing, used only for the pre-task cost estimate shown to the
# user before running. Actual cost per call comes from the `claude` CLI's own
# reported total_cost_usd, which may be $0 if covered by a subscription plan.
MODEL_PRICING = {
    "default": {"input": 3.00, "output": 15.00}
}


@dataclass
class TokenUsage:
    """Track token usage and actual reported cost for a single call."""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def cost(self) -> float:
        """Actual cost in USD as reported by the claude CLI for this call."""
        return self.cost_usd


@dataclass
class SessionStats:
    """Track cumulative stats for an AI session."""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_calls: int = 0
    total_cost: float = 0.0
    calls: list = field(default_factory=list)

    def add(self, usage: TokenUsage):
        """Add usage from a single call."""
        self.total_input_tokens += usage.input_tokens
        self.total_output_tokens += usage.output_tokens
        self.total_calls += 1
        self.total_cost += usage.cost()
        self.calls.append(usage)


class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    DIM = '\033[2m'
    NC = '\033[0m'


class AIClient:
    """Centralized AI client that shells out to the `claude` CLI."""

    def __init__(
        self,
        model: Optional[str] = None,
        max_retries: int = 5,
        timeout_seconds: int = 180
    ):
        # model=None uses whatever default model this shell's `claude` is configured for.
        self.model = model
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self.stats = SessionStats()

    def estimate_cost(
        self,
        num_items: int,
        avg_input_tokens: int = 2000,
        avg_output_tokens: int = 500
    ) -> float:
        """Rough pre-task cost estimate for a batch of AI calls.

        This is a ballpark figure only - actual cost (which may be $0 under a
        subscription plan) is tracked per-call from the claude CLI's own reporting.

        Args:
            num_items: Number of items to process
            avg_input_tokens: Average input tokens per item (prompt + content)
            avg_output_tokens: Average output tokens per item

        Returns:
            Estimated cost in USD
        """
        pricing = MODEL_PRICING["default"]
        total_input = num_items * avg_input_tokens
        total_output = num_items * avg_output_tokens

        input_cost = (total_input / 1_000_000) * pricing["input"]
        output_cost = (total_output / 1_000_000) * pricing["output"]

        return input_cost + output_cost

    def call(
        self,
        prompt: str,
        content: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0
    ) -> tuple[str, TokenUsage]:
        """Make an AI call via the `claude` CLI, with token tracking.

        Args:
            prompt: The system/instruction prompt
            content: Additional content to process (the user turn)
            max_tokens: Unused (the claude CLI does not expose a max-tokens flag) -
                kept for API compatibility with callers.
            temperature: Unused for the same reason.

        Returns:
            Tuple of (response_text, token_usage)
        """
        cmd = [
            "claude", "-p",
            "--system-prompt", prompt,
            "--disallowed-tools", "*",
            "--output-format", "json",
        ]
        if self.model:
            cmd += ["--model", self.model]
        cmd.append(content if content else prompt)

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )

                if proc.returncode != 0:
                    raise RuntimeError(f"claude CLI exited {proc.returncode}: {proc.stderr.strip()[:500]}")

                data = json.loads(proc.stdout)

                if data.get("is_error"):
                    raise RuntimeError(f"claude CLI error: {str(data.get('result'))[:500]}")

                usage_data = data.get("usage", {})
                usage = TokenUsage(
                    input_tokens=usage_data.get("input_tokens", 0),
                    output_tokens=usage_data.get("output_tokens", 0),
                    cache_read_tokens=usage_data.get("cache_read_input_tokens", 0),
                    cache_creation_tokens=usage_data.get("cache_creation_input_tokens", 0),
                    cost_usd=data.get("total_cost_usd", 0.0),
                    model=self.model or "default",
                )
                self.stats.add(usage)

                return data.get("result", ""), usage

            except (subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError) as e:
                last_error = e
                message = str(e).lower()
                if 'throttl' in message or 'rate' in message or 'overload' in message or isinstance(e, subprocess.TimeoutExpired):
                    if attempt < self.max_retries - 1:
                        wait_time = (2 ** attempt) + random.random()
                        time.sleep(wait_time)
                        continue
                raise

        raise last_error or Exception("Max retries exceeded")

    def get_summary(self) -> str:
        """Get a summary of token usage and costs."""
        return (
            f"AI Usage Summary:\n"
            f"  Calls:         {self.stats.total_calls}\n"
            f"  Input tokens:  {self.stats.total_input_tokens:,}\n"
            f"  Output tokens: {self.stats.total_output_tokens:,}\n"
            f"  Total tokens:  {self.stats.total_input_tokens + self.stats.total_output_tokens:,}\n"
            f"  Total cost:    ${self.stats.total_cost:.4f}"
        )

    def print_summary(self):
        """Print a formatted summary."""
        print(f"\n{Colors.BLUE}{'=' * 50}{Colors.NC}")
        print(f"{Colors.BLUE}AI Usage Summary{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 50}{Colors.NC}")
        print(f"  Calls:         {self.stats.total_calls}")
        print(f"  Input tokens:  {self.stats.total_input_tokens:,}")
        print(f"  Output tokens: {self.stats.total_output_tokens:,}")
        print(f"  Total cost:    {Colors.GREEN}${self.stats.total_cost:.4f}{Colors.NC}")

    def log_call(self, item_name: str, usage: TokenUsage):
        """Log a single call's usage."""
        cost = usage.cost()
        print(f"{Colors.DIM}  [{item_name}] {usage.input_tokens}→{usage.output_tokens} tokens (${cost:.4f}){Colors.NC}")


def confirm_cost(estimated_cost: float, num_items: int, threshold: float = 0.50) -> bool:
    """Prompt user to confirm if estimated cost exceeds threshold.

    Args:
        estimated_cost: Estimated cost in USD
        num_items: Number of items to process
        threshold: Cost threshold that triggers confirmation (default $0.50)

    Returns:
        True if user confirms or cost is below threshold
    """
    if estimated_cost < threshold:
        return True

    print(f"\n{Colors.YELLOW}[COST ESTIMATE]{Colors.NC}")
    print(f"  Items to process: {num_items}")
    print(f"  Estimated cost:   ${estimated_cost:.2f} (ballpark - actual may be $0 under a subscription plan)")

    while True:
        choice = input(f"\nProceed? [y/n]: ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        if choice in ['n', 'no']:
            return False
        print("Please enter 'y' or 'n'")


# Global session stats for tracking across modules
_global_stats = SessionStats()
_global_stats_lock = threading.Lock()


def get_global_stats() -> SessionStats:
    """Get the global session stats."""
    return _global_stats


def add_usage(usage: TokenUsage):
    """Add usage to global stats (thread-safe)."""
    with _global_stats_lock:
        _global_stats.add(usage)


def reset_global_stats():
    """Reset global stats for a new session."""
    global _global_stats
    with _global_stats_lock:
        _global_stats = SessionStats()


def print_global_summary():
    """Print the global usage summary."""
    stats = _global_stats
    print(f"\n{Colors.BLUE}{'=' * 50}{Colors.NC}")
    print(f"{Colors.BLUE}AI Usage Summary{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 50}{Colors.NC}")
    print(f"  Calls:         {stats.total_calls}")
    print(f"  Input tokens:  {stats.total_input_tokens:,}")
    print(f"  Output tokens: {stats.total_output_tokens:,}")
    print(f"  Total cost:    {Colors.GREEN}${stats.total_cost:.4f}{Colors.NC}")


if __name__ == "__main__":
    # Quick test
    print("AI Client module loaded successfully")
    print("\nUses the `claude` CLI already logged in to this shell - no AWS/Bedrock credentials needed.")
