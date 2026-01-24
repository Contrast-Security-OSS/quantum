#!/usr/bin/env python3
"""
ai_client.py: Centralized AI client with token tracking and cost estimation.

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

import boto3
import json
import time
import random
import threading
from dataclasses import dataclass, field
from typing import Any, Optional


# Pricing per 1M tokens (as of Jan 2025)
# https://aws.amazon.com/bedrock/pricing/
MODEL_PRICING = {
    # Claude 3.5 Sonnet
    "anthropic.claude-3-5-sonnet-20241022-v2:0": {"input": 3.00, "output": 15.00},
    "us.anthropic.claude-3-5-sonnet-20241022-v2:0": {"input": 3.00, "output": 15.00},
    # Claude 3.5 Sonnet v1
    "anthropic.claude-3-5-sonnet-20240620-v1:0": {"input": 3.00, "output": 15.00},
    # Claude Sonnet 4
    "us.anthropic.claude-sonnet-4-20250514-v1:0": {"input": 3.00, "output": 15.00},
    "anthropic.claude-sonnet-4-20250514-v1:0": {"input": 3.00, "output": 15.00},
    # Claude 3 Haiku (cheap)
    "anthropic.claude-3-haiku-20240307-v1:0": {"input": 0.25, "output": 1.25},
    # Default fallback
    "default": {"input": 3.00, "output": 15.00}
}


@dataclass
class TokenUsage:
    """Track token usage for a single call."""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def cost(self) -> float:
        """Calculate cost in USD."""
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING["default"])
        input_cost = (self.input_tokens / 1_000_000) * pricing["input"]
        output_cost = (self.output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost


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
    """Centralized AI client with token tracking."""

    def __init__(
        self,
        model: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        region: str = "us-east-2",
        profile: str = "architecture",
        max_retries: int = 5
    ):
        self.model = model
        self.region = region
        self.profile = profile
        self.max_retries = max_retries
        self.stats = SessionStats()
        self._client = None

    @property
    def client(self):
        """Lazy-load Bedrock client."""
        if self._client is None:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            self._client = session.client("bedrock-runtime")
        return self._client

    def estimate_cost(
        self,
        num_items: int,
        avg_input_tokens: int = 2000,
        avg_output_tokens: int = 500
    ) -> float:
        """Estimate cost for a batch of AI calls.

        Args:
            num_items: Number of items to process
            avg_input_tokens: Average input tokens per item (prompt + content)
            avg_output_tokens: Average output tokens per item

        Returns:
            Estimated cost in USD
        """
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING["default"])
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
        """Make an AI call with token tracking.

        Args:
            prompt: The system/instruction prompt
            content: Additional content to process
            max_tokens: Maximum output tokens
            temperature: Model temperature

        Returns:
            Tuple of (response_text, token_usage)
        """
        full_prompt = prompt
        if content:
            full_prompt = f"{prompt}\n\n---\n\n{content}"

        usage = TokenUsage(model=self.model)

        for attempt in range(self.max_retries):
            try:
                response = self.client.converse(
                    modelId=self.model,
                    messages=[
                        {
                            "role": "user",
                            "content": [{"text": full_prompt}]
                        }
                    ],
                    inferenceConfig={
                        "maxTokens": max_tokens,
                        "temperature": temperature
                    }
                )

                # Extract token usage from response
                response_usage = response.get('usage', {})
                usage.input_tokens = response_usage.get('inputTokens', 0)
                usage.output_tokens = response_usage.get('outputTokens', 0)

                # Track in session stats
                self.stats.add(usage)

                # Extract text from response
                output = response.get('output', {})
                message = output.get('message', {})
                content_list = message.get('content', [])

                if content_list and 'text' in content_list[0]:
                    return content_list[0]['text'], usage
                return str(response), usage

            except Exception as e:
                if 'throttl' in str(e).lower() or 'rate' in str(e).lower():
                    if attempt < self.max_retries - 1:
                        wait_time = (2 ** attempt) + random.random()
                        time.sleep(wait_time)
                    else:
                        raise
                else:
                    raise

        raise Exception("Max retries exceeded")

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
    print(f"  Estimated cost:   ${estimated_cost:.2f}")
    print(f"  Model:            Claude Sonnet 4")

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

    # Show pricing info
    print("\nModel Pricing (per 1M tokens):")
    for model, pricing in MODEL_PRICING.items():
        if model != "default":
            print(f"  {model}:")
            print(f"    Input:  ${pricing['input']:.2f}")
            print(f"    Output: ${pricing['output']:.2f}")
