import json
from pathlib import Path

from app.schemas import SecurityEvent
from scripts.generate_synthetic_events import (
    EVENT_TYPES,
    build_event,
    generate_batch,
    write_jsonl,
)


class TestBuildEvent:
    def test_produces_valid_security_event(self):
        raw = build_event()
        event = SecurityEvent(**raw)
        assert event.event_id.startswith("evt-")

    def test_respects_event_type_param(self):
        for et in EVENT_TYPES:
            raw = build_event(event_type=et)
            assert raw["event_type"] == et

    def test_respects_profile_param(self):
        for profile in ["benign", "suspicious", "malicious"]:
            raw = build_event(profile=profile)
            SecurityEvent(**raw)

    def test_unique_event_ids(self):
        ids = {build_event()["event_id"] for _ in range(100)}
        assert len(ids) == 100


class TestGenerateBatch:
    def test_correct_count(self):
        events = generate_batch(50)
        assert len(events) == 50

    def test_covers_all_event_types(self):
        events = generate_batch(50)
        types_seen = {e["event_type"] for e in events}
        assert types_seen == set(EVENT_TYPES)

    def test_all_events_valid_against_schema(self):
        events = generate_batch(100)
        for raw in events:
            SecurityEvent(**raw)

    def test_small_batch_still_covers_all_types(self):
        events = generate_batch(5)
        assert len(events) == 5
        types_seen = {e["event_type"] for e in events}
        assert types_seen == set(EVENT_TYPES)


class TestWriteJsonl:
    def test_writes_valid_jsonl(self, tmp_path):
        output = tmp_path / "test_events.jsonl"
        events = generate_batch(20)
        write_jsonl(events, output)

        assert output.exists()
        lines = output.read_text().strip().split("\n")
        assert len(lines) == 20

        for line in lines:
            data = json.loads(line)
            SecurityEvent(**data)

    def test_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "nested" / "deep" / "events.jsonl"
        write_jsonl(generate_batch(5), output)
        assert output.exists()

    def test_utf8_encoding(self, tmp_path):
        output = tmp_path / "utf8_test.jsonl"
        write_jsonl(generate_batch(10), output)
        content = output.read_text(encoding="utf-8")
        assert len(content) > 0
