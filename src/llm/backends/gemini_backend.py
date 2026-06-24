"""Gemini backend (google-genai, function calling).

Implemented to the documented google-genai function-calling shape. Gemini has no
tool-call ID, so we key tool results by function name (fine unless the model calls the
same tool twice in one turn). Verify against your chosen model on first use.
"""
from __future__ import annotations

from ..base import LLMResponse, ToolCall, is_neutral


class GeminiBackend:
    provider = "gemini"
    # env: GEMINI_API_KEY (or GOOGLE_API_KEY)

    def __init__(self):
        from google import genai
        self._genai = genai
        self._client = genai.Client()

    def complete(self, model, system, history, tools, effort, max_tokens) -> LLMResponse:
        from google.genai import types
        contents = [self._to_content(t, types) for t in history]

        config_kwargs = dict(system_instruction=system, max_output_tokens=max_tokens)
        if tools:
            decls = [types.FunctionDeclaration(
                        name=t["name"], description=t["description"], parameters=t["input_schema"])
                     for t in tools]
            config_kwargs["tools"] = [types.Tool(function_declarations=decls)]
        config = types.GenerateContentConfig(**config_kwargs)

        resp = self._client.models.generate_content(model=model, contents=contents, config=config)
        cand = resp.candidates[0]
        parts = cand.content.parts or []

        text_parts, tool_calls = [], []
        for p in parts:
            fc = getattr(p, "function_call", None)
            if fc is not None:
                tool_calls.append(ToolCall(fc.name, fc.name, dict(fc.args or {})))
            elif getattr(p, "text", None):
                text_parts.append(p.text)
        stop = "tool_use" if tool_calls else "end_turn"
        return LLMResponse("".join(text_parts), tool_calls, cand.content, stop)

    @staticmethod
    def _to_content(turn, types):
        if not is_neutral(turn):
            return turn  # native types.Content passthrough
        content = turn["content"]
        if isinstance(content, str):
            return types.Content(role="user", parts=[types.Part.from_text(text=content)])
        parts = []
        for blk in content:
            if blk["type"] == "tool_result":
                parts.append(types.Part.from_function_response(
                    name=blk["tool_use_id"], response={"result": blk["content"]}))
            elif blk["type"] == "text":
                parts.append(types.Part.from_text(text=blk["text"]))
        return types.Content(role="user", parts=parts)
