"""Anthropic backend (the verified default).

Uses adaptive thinking + effort, a cached system prompt, and streaming. Assistant
turns are stored as the raw response content so thinking-block signatures are
preserved across the tool-use loop.
"""
from __future__ import annotations

from ..base import LLMResponse, ToolCall, is_neutral


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
        kwargs = dict(
            model=model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={"effort": effort},
        )
        if tools:
            kwargs["tools"] = [
                {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
                for t in tools
            ]
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
        return LLMResponse("".join(text_parts), tool_calls, assistant_turn, stop)

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
