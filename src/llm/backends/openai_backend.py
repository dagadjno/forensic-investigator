"""OpenAI backend (Chat Completions + function calling).

Implemented to the documented Chat Completions tool-calling shape. Verify against your
chosen model on first use (reasoning vs. non-reasoning models differ in parameters).
"""
from __future__ import annotations

import json

from ..base import LLMResponse, ToolCall, is_neutral


class OpenAIBackend:
    provider = "openai"
    # env: OPENAI_API_KEY

    def __init__(self):
        from openai import OpenAI
        self._client = OpenAI(max_retries=8)

    def complete(self, model, system, history, tools, effort, max_tokens) -> LLMResponse:
        messages = [{"role": "system", "content": system}]
        for t in history:
            messages.extend(self._to_msgs(t))
        kwargs = dict(model=model, messages=messages, max_completion_tokens=max_tokens)
        if tools:
            kwargs["tools"] = [
                {"type": "function", "function": {
                    "name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
                for t in tools
            ]
        resp = self._client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message

        tool_calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(tc.id, tc.function.name, args))
        stop = "tool_use" if tool_calls else "end_turn"

        native = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            native["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        assistant_turn = {"_provider": "openai", "message": native}
        return LLMResponse(msg.content or "", tool_calls, assistant_turn, stop)

    @staticmethod
    def _to_msgs(turn):
        if isinstance(turn, dict) and turn.get("_provider") == "openai":
            return [turn["message"]]
        if is_neutral(turn):
            content = turn["content"]
            if isinstance(content, str):
                return [{"role": "user", "content": content}]
            out = []
            for blk in content:
                if blk["type"] == "tool_result":
                    out.append({"role": "tool", "tool_call_id": blk["tool_use_id"],
                                "content": blk["content"]})
                elif blk["type"] == "text":
                    out.append({"role": "user", "content": blk["text"]})
            return out
        return [turn]
