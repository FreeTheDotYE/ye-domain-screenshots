#!/usr/bin/env python3
"""Validate the public, day-precision .YE screenshot evidence repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^images/sha256/([0-9a-f]{2})/([0-9a-f]{64})\.jpg$")
OBSERVATION_RE = re.compile(r"^observations/([0-9]{4})/(0[1-9]|1[0-2])\.jsonl$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ye$"
)
CURRENT_KEYS = {
    "schema_version",
    "domain",
    "url",
    "final_url",
    "http_status",
    "content_type",
    "image_sha256",
    "image_path",
    "capture_date",
    "last_checked_date",
    "width",
    "height",
}
OBSERVATION_KEYS = {
    "schema_version",
    "observed_date",
    "domain",
    "url",
    "final_url",
    "http_status",
    "content_type",
    "image_sha256",
    "image_path",
    "width",
    "height",
    "classification",
    "screenshot_id",
}
RUN_KEYS = {
    "schema_version",
    "date",
    "candidate_domains",
    "attempted",
    "successful",
    "changed",
    "unchanged",
    "failed",
    "current_screenshots",
    "images",
    "total_observations",
    "vantage",
}
FIXED_FILES = {
    ".github/workflows/validate.yml",
    "README.md",
    "RIGHTS.md",
    "current.jsonl",
    "runs/latest.json",
    "scripts/validate.py",
}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_object(value: object) -> str:
    return digest_bytes(canonical_json(value).encode("utf-8"))


def valid_date(value: object, *, allow_empty: bool = False) -> bool:
    if allow_empty and value == "":
        return True
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def valid_url(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            rows.append(value)
    expected = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
    if path.read_bytes() != expected:
        raise ValueError(f"non-canonical JSONL: {path}")
    return rows


def common_row(row: dict, keys: set[str], date_field: str) -> None:
    if set(row) != keys or row.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected screenshot row schema")
    domain = row.get("domain")
    if not isinstance(domain, str) or not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"invalid .YE domain: {domain}")
    if not valid_url(row.get("url")) or not valid_url(row.get("final_url")):
        raise ValueError(f"invalid screenshot URL for {domain}")
    if (
        not isinstance(row.get("http_status"), int)
        or isinstance(row["http_status"], bool)
        or not 200 <= row["http_status"] <= 399
    ):
        raise ValueError(f"invalid HTTP status for {domain}")
    content_type = row.get("content_type")
    if (
        not isinstance(content_type, str)
        or len(content_type) > 200
        or not (
            content_type.lower().startswith("text/html")
            or content_type.lower().startswith("application/xhtml+xml")
        )
    ):
        raise ValueError(f"invalid web content type for {domain}")
    digest = row.get("image_sha256")
    image_path = row.get("image_path")
    match = IMAGE_RE.fullmatch(str(image_path))
    if (
        not isinstance(digest, str)
        or not HEX_RE.fullmatch(digest)
        or not match
        or match.group(1) != digest[:2]
        or match.group(2) != digest
    ):
        raise ValueError(f"invalid screenshot image reference for {domain}")
    if row.get("width") != 1365 or row.get("height") != 768:
        raise ValueError(f"unexpected screenshot viewport for {domain}")
    if not valid_date(row.get(date_field)):
        raise ValueError(f"invalid screenshot date for {domain}")


def repository_files(root: Path) -> dict[str, str]:
    files = {}
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts:
            continue
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed: {path}")
        if not path.is_file() or path.name == "MANIFEST.sha256":
            continue
        relative = path.relative_to(root).as_posix()
        if (
            relative not in FIXED_FILES
            and not IMAGE_RE.fullmatch(relative)
            and not OBSERVATION_RE.fullmatch(relative)
        ):
            raise ValueError(f"unexpected public file: {relative}")
        files[relative] = digest_bytes(path.read_bytes())
    return files


def write_manifest(root: Path) -> None:
    files = repository_files(root)
    body = "".join(f"{digest}  {relative}\n" for relative, digest in files.items())
    (root / "MANIFEST.sha256").write_text(body, encoding="ascii")


def validate_manifest(root: Path) -> None:
    declared = {}
    for line in (root / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\s].*)", line)
        if not match or match.group(2) in declared:
            raise ValueError("invalid or duplicate manifest row")
        declared[match.group(2)] = match.group(1)
    if declared != repository_files(root):
        raise ValueError("MANIFEST.sha256 does not match repository files")


def validate_images(root: Path, observations: list[dict]) -> set[str]:
    referenced = {row["image_path"] for row in observations}
    actual = set()
    for path in sorted((root / "images").rglob("*.jpg")) if (root / "images").exists() else []:
        relative = path.relative_to(root).as_posix()
        match = IMAGE_RE.fullmatch(relative)
        body = path.read_bytes()
        if (
            not match
            or match.group(1) != match.group(2)[:2]
            or digest_bytes(body) != match.group(2)
            or len(body) < 4
            or not body.startswith(b"\xff\xd8\xff")
            or not body.endswith(b"\xff\xd9")
            or len(body) > 2_500_000
        ):
            raise ValueError(f"invalid screenshot image: {relative}")
        actual.add(relative)
    if actual != referenced:
        raise ValueError("screenshot images and observation references do not reconcile")
    return actual


def validate(root: Path) -> dict:
    observations = []
    observation_ids = set()
    for path in sorted((root / "observations").glob("*/*.jsonl")) if (root / "observations").exists() else []:
        match = OBSERVATION_RE.fullmatch(path.relative_to(root).as_posix())
        if not match:
            raise ValueError(f"invalid observation path: {path}")
        rows = load_jsonl(path)
        ordering = []
        for row in rows:
            common_row(row, OBSERVATION_KEYS, "observed_date")
            if row["classification"] not in {"initial", "changed"}:
                raise ValueError("invalid screenshot classification")
            payload = dict(row)
            screenshot_id = payload.pop("screenshot_id")
            if (
                not isinstance(screenshot_id, str)
                or not HEX_RE.fullmatch(screenshot_id)
                or screenshot_id != digest_object(payload)
                or screenshot_id in observation_ids
            ):
                raise ValueError("invalid or duplicate screenshot identifier")
            if row["observed_date"][:7] != f"{match.group(1)}-{match.group(2)}":
                raise ValueError("observation date does not match its monthly path")
            observation_ids.add(screenshot_id)
            observations.append(row)
            ordering.append((row["observed_date"], row["domain"], screenshot_id))
        if ordering != sorted(ordering):
            raise ValueError(f"observations are not sorted: {path}")

    current = load_jsonl(root / "current.jsonl")
    domains = []
    by_domain: dict[str, list[dict]] = {}
    for row in observations:
        by_domain.setdefault(row["domain"], []).append(row)
    for row in current:
        common_row(row, CURRENT_KEYS, "capture_date")
        if not valid_date(row.get("last_checked_date")):
            raise ValueError("invalid last-checked date")
        if row["last_checked_date"] < row["capture_date"]:
            raise ValueError("last-checked date precedes the capture")
        domains.append(row["domain"])
        matching = [
            item
            for item in by_domain.get(row["domain"], [])
            if item["observed_date"] == row["capture_date"]
            and item["image_sha256"] == row["image_sha256"]
            and item["url"] == row["url"]
            and item["final_url"] == row["final_url"]
        ]
        if not matching:
            raise ValueError(f"current screenshot lacks matching history: {row['domain']}")
    if domains != sorted(set(domains)):
        raise ValueError("current screenshot rows are not uniquely sorted")

    images = validate_images(root, observations)
    run = json.loads((root / "runs/latest.json").read_text(encoding="utf-8"))
    if not isinstance(run, dict) or set(run) != RUN_KEYS:
        raise ValueError("unexpected run summary schema")
    if run["schema_version"] != SCHEMA_VERSION or run["vantage"] != "external-web":
        raise ValueError("invalid run summary metadata")
    if not valid_date(run["date"], allow_empty=True):
        raise ValueError("invalid run date")
    count_fields = RUN_KEYS - {"schema_version", "date", "vantage"}
    if any(
        not isinstance(run[field], int)
        or isinstance(run[field], bool)
        or run[field] < 0
        for field in count_fields
    ):
        raise ValueError("invalid run summary count")
    if (
        run["attempted"] != run["successful"] + run["failed"]
        or run["successful"] != run["changed"] + run["unchanged"]
        or run["current_screenshots"] != len(current)
        or run["images"] != len(images)
        or run["total_observations"] != len(observations)
    ):
        raise ValueError("run summary totals do not reconcile")
    if run["date"] == "" and any(run[field] for field in count_fields):
        raise ValueError("uninitialized run summary contains counts")
    validate_manifest(root)
    return {
        "current_screenshots": len(current),
        "images": len(images),
        "observations": len(observations),
        "ok": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.write_manifest:
        write_manifest(root)
    print(json.dumps(validate(root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
