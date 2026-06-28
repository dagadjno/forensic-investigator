"""Anthropic backend (the verified default).

Uses adaptive thinking + effort, a cached system prompt, and streaming. Assistant
turns are stored as the raw response content so thinking-block signatures are
preserved across the tool-use loop.
"""
from __future__ import annotations

from ..base import LLMResponse, ToolCall, is_neutral


def _cache_last_block(messages) -> None:
    """Put a cache breakpoint on the last content block of the latest message, so the whole
    conversation prefix (which only grows across tool-call rounds) is read from cache on the
    next round. Up to 4 breakpoints allowed; we use tools + system + this = 3."""
    if not messages or not isinstance(messages[-1], dict):
        return
    content = messages[-1].get("content")
    if isinstance(content, str):
        messages[-1]["content"] = [{"type": "text", "text": content,
                                    "cache_control": {"type": "ephemeral"}}]
    elif isinstance(content, list) and content and isinstance(content[-1], dict):
        content[-1]["cache_control"] = {"type": "ephemeral"}


class AnthropicBackend:
    provider = "anthropic"
    # env: ANTHROPIC_API_KEY

    def __init__(self):
        import anthropic
        # The SDK retries 429/529/5xx with exponential backoff; bump from the default
        # 2 so transient "Overloaded" errors don't kill a long run.
        self._client = anthropic.Anthropic(max_retries=8)

    def complete(self, model, system, history, tools, effort, max_tokens) -> LLMResponse:
        messages = [self._to_msg(t) for t in history]
        _cache_last_block(messages)   # cache the (only-growing) conversation prefix
        kwargs = dict(
            model=model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={"effort": effort},
        )
        if tools:
            tool_list = [
                {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
                for t in tools
            ]
            # Cache the static, sizable tool schemas — otherwise re-sent at full price every round.
            tool_list[-1]["cache_control"] = {"type": "ephemeral"}
            kwargs["tools"] = tool_list
        with self._client.messages.stream(**kwargs) as stream:
            msg = stream.get_final_message()

        text_parts, tool_calls = [], []
        for b in msg.content:
            if b.type == "text":
                text_parts.append(b.text)
            elif b.type == "tool_use":
                tool_calls.append(ToolCall(b.id, b.name, dict(b.input)))
        stop = "tool_use" if msg.stop_reason == "tool_use" else "end_turn"
        # Pass raw content back as the assistant turn (preserves thinking blocks).
        assistant_turn = {"role": "assistant", "content": msg.content}
        u = getattr(msg, "usage", None)
        usage = {
            "input_tokens": getattr(u, "input_tokens", 0) or 0,
            "output_tokens": getattr(u, "output_tokens", 0) or 0,
            "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
            "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
        } if u else {}
        return LLMResponse("".join(text_parts), tool_calls, assistant_turn, stop, usage=usage)

    @staticmethod
    def _to_msg(turn):
        if not is_neutral(turn):
            return turn  # native assistant turn passthrough
        content = turn["content"]
        if isinstance(content, str):
            return {"role": "user", "content": content}
        blocks = []
        for blk in content:
            if blk["type"] == "tool_result":
                blocks.append({"type": "tool_result", "tool_use_id": blk["tool_use_id"],
                               "content": blk["content"], "is_error": blk.get("is_error", False)})
            elif blk["type"] == "text":
                blocks.append({"type": "text", "text": blk["text"]})
        return {"role": "user", "content": blocks}
