"""Extract raw events per sourcetype from Splunk journal.gz files.

Splunk rawdata journal layout (observed): gzip payload contains segments;
each segment has metadata lines (host::, source::, sourcetype::) followed by
raw event bytes. This parser splits on sourcetype markers and carves printable
event blobs between binary framing.

Output: data/raw/events/<sourcetype>.jsonl with {sourcetype, host, raw}.
"""
import gzip
import re
from collections import Counter
from pathlib import Path

JOURNALS = [
    "data/raw/attack/botsv1_data_set/var/lib/splunk/botsv1/db/"
    "db_1470868141_1470799731_28/rawdata/journal.gz",
    "data/raw/attack/botsv1_data_set/var/lib/splunk/botsv1/db/"
    "db_1472063264_1472053148_48/rawdata/journal.gz",
]

MARKER = re.compile(rb"sourcetype::([A-Za-z0-9:_.\-]+)")


def carve_events(blob: bytes, sourcetype: str, host: str) -> list[dict]:
    """Split a segment blob into printable event strings."""
    # Events are separated by Splunk framing; carve runs of printable text
    # longer than a threshold, then split obvious XML/JSON boundaries.
    text = blob.decode("utf-8", errors="ignore")
    chunks = re.split(r"[\x00-\x08\x0b\x0c\x0e-\x1f]{3,}", text)
    events = []
    for ch in chunks:
        ch = ch.strip()
        if len(ch) < 60:
            continue
        # Drop metadata echo lines
        if ch.startswith("host::") or ch.startswith("source::"):
            continue
        events.append({"sourcetype": sourcetype, "host": host, "raw": ch[:8000]})
    return events


def main() -> None:
    out_dir = Path("data/raw/events")
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter = Counter()
    for journal in JOURNALS:
        print("reading", journal, flush=True)
        with gzip.open(journal, "rb") as f:
            data = f.read()
        print("  bytes:", len(data), flush=True)
        # Find segments: host marker ... sourcetype marker ... event blob
        # up to next host marker.
        host_marks = list(re.finditer(rb"host::([A-Za-z0-9:_\-.]+)", data))
        print("  host markers:", len(host_marks), flush=True)
        for i, hm in enumerate(host_marks):
            host = hm.group(1).decode()
            seg = data[hm.start(): host_marks[i + 1].start() if i + 1 < len(host_marks) else len(data)]
            stm = MARKER.search(seg)
            if not stm:
                continue
            sourcetype = stm.group(1).decode()
            safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", sourcetype)
            body = seg[stm.end():]
            events = carve_events(body, sourcetype, host)
            if not events:
                continue
            with open(out_dir / f"{safe}.jsonl", "a", encoding="utf-8") as f:
                import json
                for ev in events:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            counts[sourcetype] += len(events)
        print("  done", journal, flush=True)
    print("event counts per sourcetype:", flush=True)
    for st, n in counts.most_common():
        print(f"  {st} x{n}", flush=True)


if __name__ == "__main__":
    main()
