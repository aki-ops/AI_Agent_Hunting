"""Independent LLM transport probe for hidden gateway context.

Does not import the hunting engine and does not contact Splunk.
Sends A1-A6 against the configured OpenAI-compatible endpoint and records
every physical HTTP attempt.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from http.client import HTTPResponse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

COMPILER_SYSTEM = (
    "You are the semantic compilation stage of a threat-hunting system. "
    "Convert the user's hunt request into ONLY the JSON contract described "
    "in the user prompt. Do not answer the hunt, write a report, invent a "
    "verdict, or emit SPL/KQL/vendor queries. Output JSON only."
)
JSON_SYSTEM = "Return JSON"
TINY_USER = "x"
TAEDONGGANG_REQUEST = (
    "A Federal law enforcement agency reports that Taedonggang often spear "
    "phishes its victims with zip files that have to be opened with a password. "
    "What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?"
)


def load_dotenv(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'\"")
    return env


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text or "") / 4))


def capture_compiler_prompt() -> str:
    from hunting.compiler.compiler import KnowledgeBehaviorCompiler
    from hunting.contracts.hunt import HuntRequest, HuntRequestKind

    captured: dict[str, str] = {}

    def _grab(prompt: str, reason: str = "", phase: Any | None = None) -> str:
        # compile() may issue a repair prompt after the first intentionally
        # invalid fixture response.  C1 diagnosis must measure the initial
        # prompt, not the repair prompt.
        captured.setdefault("prompt", prompt)
        return "{}"

    compiler = KnowledgeBehaviorCompiler(llm_caller=_grab)
    request = HuntRequest("req-diagnose-c1", HuntRequestKind.NL_QUESTION, TAEDONGGANG_REQUEST)
    try:
        compiler.compile(request)
    except Exception:
        pass
    if "prompt" not in captured:
        raise RuntimeError("failed to capture the real C1 compiler prompt")
    return captured["prompt"]


def request_chars(system_prompt: str | None, user_prompt: str) -> int:
    return len(system_prompt or "") + len(user_prompt or "")


def post_chat(
    *,
    endpoint: str,
    api_key: str,
    model: str,
    system_prompt: str | None,
    user_prompt: str,
    max_tokens: int,
    timeout_seconds: int,
    stream: bool,
    attempt: int,
    test_id: str,
    phase: str,
) -> dict[str, Any]:
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.0,
        "max_tokens": max_tokens,
        "stream": stream,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AI-Agent-Hunting-diagnose/1.0",
        },
        method="POST",
    )
    record: dict[str, Any] = {
        "request_id": f"{test_id}-{uuid.uuid4().hex[:8]}",
        "test_id": test_id,
        "configured_model": model,
        "actual_model": None,
        "phase": phase,
        "stream": stream,
        "request_chars": request_chars(system_prompt, user_prompt),
        "locally_estimated_tokens": estimate_tokens((system_prompt or "") + (user_prompt or "")),
        "provider_reported_prompt_tokens": None,
        "provider_reported_completion_tokens": None,
        "first_byte_ms": None,
        "total_ms": None,
        "http_status": None,
        "attempt": attempt,
        "retry_after": None,
        "error": None,
        "hidden_token_delta": None,
    }
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            record["http_status"] = int(getattr(resp, "status", 200) or 200)
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                record["retry_after"] = retry_after
            content_type = resp.headers.get("Content-Type", "")
            if stream and (
                (isinstance(content_type, str) and "text/event-stream" in content_type.lower())
                or isinstance(resp, HTTPResponse)
            ) and callable(getattr(resp, "readline", None)):
                lines: list[bytes] = []
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    if record["first_byte_ms"] is None:
                        record["first_byte_ms"] = round((time.perf_counter() - started) * 1000.0, 1)
                    lines.append(line)
                raw = b"".join(lines)
            else:
                first = resp.read(1)
                record["first_byte_ms"] = round((time.perf_counter() - started) * 1000.0, 1)
                raw = first + resp.read()
            record["total_ms"] = round((time.perf_counter() - started) * 1000.0, 1)
        raw_text = raw.decode("utf-8", errors="replace")
        parsed: dict[str, Any] = {}
        usage: dict[str, Any] = {}
        if raw_text.lstrip().startswith("data:"):
            for line in raw_text.splitlines():
                if line.strip() == "data: [DONE]" or not line.strip().startswith("data:"):
                    continue
                try:
                    chunk = json.loads(line.split(":", 1)[1].strip())
                except (ValueError, IndexError):
                    continue
                if not isinstance(chunk, dict):
                    continue
                parsed = chunk
                usage.update(chunk.get("usage") or {})
        else:
            parsed = json.loads(raw_text)
            usage = parsed.get("usage") or parsed.get("usageMetadata") or {}
        prompt_tokens = (
            usage.get("prompt_tokens")
            or usage.get("promptTokenCount")
            or usage.get("input_tokens")
        )
        completion_tokens = (
            usage.get("completion_tokens")
            or usage.get("candidatesTokenCount")
            or usage.get("output_tokens")
        )
        if prompt_tokens is not None:
            record["provider_reported_prompt_tokens"] = int(prompt_tokens)
            record["hidden_token_delta"] = int(prompt_tokens) - record["locally_estimated_tokens"]
        if completion_tokens is not None:
            record["provider_reported_completion_tokens"] = int(completion_tokens)
        record["actual_model"] = (
            parsed.get("model")
            or ((parsed.get("choices") or [{}])[0].get("model") if parsed.get("choices") else None)
        )
        record["usage_keys"] = sorted(str(key) for key in usage.keys()) if isinstance(usage, dict) else []
    except urllib.error.HTTPError as exc:
        record["http_status"] = int(exc.code)
        record["retry_after"] = exc.headers.get("Retry-After") if exc.headers else None
        record["total_ms"] = round((time.perf_counter() - started) * 1000.0, 1)
        record["first_byte_ms"] = record["total_ms"]
        err_body = exc.read().decode("utf-8", errors="replace")[:500]
        record["error"] = f"HTTP {exc.code}: {err_body}"
    except Exception as exc:
        record["total_ms"] = round((time.perf_counter() - started) * 1000.0, 1)
        record["first_byte_ms"] = record["total_ms"]
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


def run_case(
    *,
    endpoint: str,
    api_key: str,
    timeout_seconds: int,
    test_id: str,
    model: str,
    system_prompt: str | None,
    user_prompt: str,
    max_tokens: int,
        phase: str,
    stream: bool,
) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for attempt in (1, 2):
        record = post_chat(
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
            attempt=attempt,
            test_id=test_id,
            phase=phase,
            stream=stream,
        )
        attempts.append(record)
        status = record.get("http_status")
        if status in {200, None} and record.get("error") is None:
            break
        if status not in {429, 500, 502, 503, 504, 524}:
            break
        time.sleep(1.5 * attempt)
    return attempts


def conclude(records: list[dict[str, Any]], auto_model: str, specific_model: str) -> dict[str, Any]:
    successful = [item for item in records if item.get("provider_reported_prompt_tokens") is not None]
    auto_ok = [item for item in successful if item["configured_model"] == auto_model]
    specific_ok = [item for item in successful if item["configured_model"] == specific_model]
    tiny = [item for item in successful if item["test_id"] in {"A1", "A2", "A3", "A4"}]
    real = [item for item in successful if item["test_id"] in {"A5", "A6"}]
    deltas = [int(item["hidden_token_delta"]) for item in successful if item.get("hidden_token_delta") is not None]
    auto_models = {item.get("actual_model") for item in auto_ok}
    findings: list[str] = []
    routed = [item for item in records if item.get("http_status") == 200 and item.get("actual_model")]
    if not successful:
        findings.append("Gateway omitted usage.prompt_tokens; hidden-token size cannot be measured from the client.")
    if routed:
        auto_routed = sorted({str(item.get("actual_model")) for item in routed if item.get("configured_model") == auto_model})
        if auto_routed:
            findings.append(f"auto is a router, not a model; it resolved to {auto_routed}.")
    timeouts = [
        item for item in records
        if "timed out" in str(item.get("error") or "").lower()
        or item.get("http_status") in {524, 504}
    ]
    if timeouts:
        ids = [item["test_id"] for item in timeouts]
        findings.append(f"Timeout on {ids}: large compiler prompt + auto-routed model, not local token-ceiling rejection.")
    if deltas and all(delta >= 1500 for delta in deltas):
        findings.append(
            "Every successful prompt is inflated by ~2000+ tokens: gateway injects shared system/context or miscounts tokens."
        )
    auto_deltas = [int(item["hidden_token_delta"]) for item in auto_ok if item.get("hidden_token_delta") is not None]
    specific_deltas = [int(item["hidden_token_delta"]) for item in specific_ok if item.get("hidden_token_delta") is not None]
    if auto_deltas and specific_deltas:
        auto_mean = sum(auto_deltas) / len(auto_deltas)
        specific_mean = sum(specific_deltas) / len(specific_deltas)
        if auto_mean - specific_mean >= 800:
            findings.append("Only auto is inflated: the auto router is adding context.")
        elif min(specific_deltas) >= 1500:
            findings.append("Specific models are also inflated: gateway adds context for every model.")
    if tiny and real:
        tiny_ratio = [item["provider_reported_prompt_tokens"] / max(item["locally_estimated_tokens"], 1) for item in tiny]
        real_ratio = [item["provider_reported_prompt_tokens"] / max(item["locally_estimated_tokens"], 1) for item in real]
        if (sum(real_ratio) / len(real_ratio)) - (sum(tiny_ratio) / len(tiny_ratio)) >= 0.4:
            findings.append("Inflation grows with prompt length: local estimator/tokenizer mismatch.")
        elif tiny and abs((sum(d for d in auto_deltas + specific_deltas) / max(len(auto_deltas + specific_deltas), 1)) - 2000) < 600:
            findings.append("Inflation is roughly constant: fixed hidden prefix, not tokenizer drift.")
    if len({item for item in auto_models if item}) > 1:
        findings.append("actual_model changed across auto calls: auto is not stable.")
    if successful and all(item.get("actual_model") in (None, "") for item in successful):
        findings.append("API did not return actual_model; only the gateway owner can name the routed model/context.")
    if not findings and successful:
        findings.append("No stable hidden-context signature; compare provider_reported_prompt_tokens to locally_estimated_tokens per row.")
    return {
        "auto_model": auto_model,
        "specific_model": specific_model,
        "successful_attempts": len(successful),
        "auto_actual_models": sorted({str(item) for item in auto_models if item}),
        "mean_hidden_token_delta": (sum(deltas) / len(deltas)) if deltas else None,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe LLM gateway hidden context without Splunk or the hunt engine.")
    parser.add_argument("--env-file", default=str(ROOT / ".env"))
    parser.add_argument("--specific-model", default=os.getenv("LLM_MODEL_SPECIFIC", "mb/gemini-3.7-flash-high"))
    parser.add_argument("--output", default=str(ROOT / "artifacts" / "llm_transport_diagnosis.jsonl"))
    parser.add_argument("--no-stream", action="store_true", help="Send non-streaming requests for comparison")
    args = parser.parse_args()

    file_env = load_dotenv(Path(args.env_file))
    combined = {**file_env, **os.environ}
    endpoint = combined.get("LLM_ENDPOINT") or (
        f"{combined.get('OPENAI_BASE_URL', '').rstrip('/')}/chat/completions"
        if combined.get("OPENAI_BASE_URL")
        else ""
    )
    api_key = combined.get("LLM_API_KEY") or combined.get("OPENAI_API_KEY") or ""
    auto_model = combined.get("LLM_MODEL") or combined.get("OPENAI_MODEL") or "auto"
    timeout_seconds = int(combined.get("LLM_TIMEOUT", "120"))
    if not endpoint or not api_key:
        print("LLM_ENDPOINT/LLM_API_KEY missing", file=sys.stderr)
        return 2

    compiler_prompt = capture_compiler_prompt()
    cases = [
        ("A1", auto_model, None, TINY_USER, 8, "PROBE"),
        ("A2", auto_model, JSON_SYSTEM, TINY_USER, 8, "PROBE"),
        ("A3", args.specific_model, None, TINY_USER, 8, "PROBE"),
        ("A4", args.specific_model, JSON_SYSTEM, TINY_USER, 8, "PROBE"),
        ("A5", auto_model, COMPILER_SYSTEM, compiler_prompt, 8, "C1_COMPILER"),
        ("A6", args.specific_model, COMPILER_SYSTEM, compiler_prompt, 8, "C1_COMPILER"),
    ]

    records: list[dict[str, Any]] = []
    for test_id, model, system_prompt, user_prompt, max_tokens, phase in cases:
        print(f"[*] {test_id} model={model} system={'yes' if system_prompt else 'no'} chars={request_chars(system_prompt, user_prompt)}")
        records.extend(
            run_case(
                endpoint=endpoint,
                api_key=api_key,
                timeout_seconds=timeout_seconds,
                test_id=test_id,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                phase=phase,
                stream=not args.no_stream,
            )
        )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records), encoding="utf-8")
    summary = conclude(records, auto_model, args.specific_model)
    summary_path = out_path.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[+] attempts: {out_path}")
    print(f"[+] summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
