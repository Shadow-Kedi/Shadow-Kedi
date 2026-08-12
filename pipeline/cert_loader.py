# pipeline/cert_loader.py
"""
CERT Insider Threat Test Dataset (r4.2) loader — replaces nslkdd_loader.py
as the second data source. Unlike NSL-KDD (packet-flow network data), this
is real behavioral insider-threat data: 1,000 synthetic users, ~17-18
months, with actual red-team malicious-insider scenarios labeled (data
exfiltration, IP theft, IT sabotage) rather than hand-specified labels.

Source: https://www.kaggle.com/datasets/andrihjonior/cert-insider-threat-dataset-r4-2
(or any r4.2 mirror with the standard file layout below)

Expected files in --data-dir (case-insensitive match, standard r4.2 names):
    logon.csv   -> LOGIN_EVENT       (id, date, user, pc, activity)
    device.csv  -> USB_CONNECT       (id, date, user, pc, activity[, file_tree])
    file.csv    -> FILE_ACCESS/TRANSFER (id, date, user, pc, filename, activity,
                                          to_removable_media, from_removable_media[, content])
    http.csv    -> BROWSER_ACTIVITY/CLOUD_UPLOAD/FILE_TRANSFER
                                      (id, date, user, pc, url, activity, size[, content])
    email.csv   -> NETWORK_CONN      (id, date, user, pc, to, cc, bcc, from,
                                       activity, size, attachments[, content])
    psychometric.csv -> NOT converted to events (per-user OCEAN traits;
                                       loaded separately, see load_psychometric())

Malicious-insider ground truth (optional): point --answers-dir at whatever
"answers"-style folder/files your r4.2 download includes. Layout varies by
mirror, so this loader searches for any CSV under that directory containing
recognizable user/date-range columns rather than assuming one fixed name.
Without an answers directory, every event is emitted with is_anomaly=False
(no ground truth available) — the honest default, not a guess.

Full r4.2 is several million rows across all five files. --limit-per-file
caps each file's row count for a first pass on a laptop; pass --full to
disable the cap.

Usage:
    python -m pipeline.cert_loader --data-dir data/raw/cert --answers-dir data/raw/cert/answers
    python -m pipeline.cert_loader --data-dir data/raw/cert --full
"""

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from pipeline.schema import EventType, RiskCategory, ShadowKediEvent

CLIENT_ID = "cert_insider_threat"  # separate tenant, like nslkdd_benchmark was
DEFAULT_ROW_CAP = 500_000  # per file, unless --full

CORE_FILES = {
    "logon": "logon.csv",
    "device": "device.csv",
    "file": "file.csv",
    "http": "http.csv",
    "email": "email.csv",
}


# ============================================================
# File discovery / parsing helpers
# ============================================================

def find_file(data_dir: Path, name: str) -> Path | None:
    """Case-insensitive filename match within data_dir (non-recursive)."""
    target = name.lower()
    for p in data_dir.iterdir():
        if p.is_file() and p.name.lower() == target:
            return p
    return None


def parse_dt(s: str) -> datetime:
    # standard CERT format: "3/6/2010 1:41:56"
    return datetime.strptime(s.strip(), "%m/%d/%Y %H:%M:%S")


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def domain_from_url(url: str) -> str | None:
    if not url:
        return None
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.netloc or None)
    except Exception:
        return None


# ============================================================
# Heuristic activity classifier for http.csv when the real `activity`
# column is unavailable. Inspects url/content transiently at load time
# only — never stores the raw content text, just the derived label —
# to stay within the license's "refer to general qualities" clause.
# This is the heuristic-IDS piece: pattern-matching, not a trained model.
# ============================================================

EXFIL_DOMAIN_HINTS = (
    "wikileaks", "pastebin", "mega.nz", "mega.co", "mediafire",
    "wetransfer", "4shared", "rapidshare", "dropbox", "drive.google",
    "anonfiles", "gofile", "transfernow",
)
DOWNLOAD_EXTENSIONS = (
    ".exe", ".zip", ".rar", ".7z", ".msi", ".dmg", ".torrent",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".pptx", ".iso",
)
# Deliberately NOT using generic content markers like "multipart/form-data"
# or "boundary=" here — those are the standard mechanics of any web upload
# form (avatars, attachments, internal business tools) and produced a false
# positive on a legitimate CRM API call in testing. Domain/extension hints
# are specific enough to be low-risk; free-text content keywords weren't.


def infer_http_activity(url: str, content: str):
    """
    Returns (EventType, inferred_label, matched_reason) using only
    lightweight pattern matching against url/content — a heuristic
    stand-in for the missing `activity` column, not a trained classifier.
    Deliberately conservative: only fires on a specific known exfil-style
    domain or a download-indicating file extension. Generic content
    keywords were tried and dropped after producing false positives on
    ordinary business traffic (see note above).
    """
    url_l = (url or "").lower()

    for hint in EXFIL_DOMAIN_HINTS:
        if hint in url_l:
            return EventType.CLOUD_UPLOAD, "upload", f"domain_hint:{hint}"

    for ext in DOWNLOAD_EXTENSIONS:
        if url_l.split("?")[0].endswith(ext):
            return EventType.FILE_TRANSFER, "download", f"url_extension:{ext}"

    return EventType.BROWSER_ACTIVITY, "browse", "no_hint_matched"


# ============================================================
# Malicious-insider ground truth
# ============================================================

def load_malicious_windows(answers_dir: str | None) -> dict:
    """
    Best-effort loader for insider-threat ground truth. Returns
    {username: [(start_dt, end_dt, scenario_label), ...]}.

    Layouts vary across r4.2 mirrors, so this scans every CSV under
    answers_dir and keeps any row where it can find a user-like column
    plus either a date range or a single date column.
    """
    windows: dict = {}
    if not answers_dir:
        return windows
    adir = Path(answers_dir)
    if not adir.exists():
        print(f"WARNING: --answers-dir {answers_dir} not found; proceeding with no ground-truth labels.")
        return windows

    csv_files = list(adir.glob("*.csv"))  # top-level only — deliberately not recursive.
    # r4.2's per-scenario subfolders (r4.2-1/, r4.2-2/, r4.2-3/) contain per-user
    # extracts derived FROM insiders.csv, not independent data, and some mirrors
    # ship them with malformed/ragged rows. insiders.csv alone is authoritative.
    skipped_subdirs = [d.name for d in adir.iterdir() if d.is_dir()]
    if skipped_subdirs:
        print(f"NOTE: skipping subfolder(s) {skipped_subdirs} under {answers_dir} — "
              f"using top-level insiders.csv as the authoritative source instead of "
              f"per-user extracts (avoids known ragged-row parsing issues in those files).")
    if not csv_files:
        print(f"WARNING: no CSV files found under {answers_dir}; proceeding with no ground-truth labels.")
        return windows

    user_cols = {"user", "user_id", "username", "insider"}
    start_cols = {"start", "start_date", "start_time"}
    end_cols = {"end", "end_date", "end_time"}
    single_date_cols = {"date"}
    scenario_cols = {"scenario", "dataset", "details"}

    loaded = 0
    for fpath in csv_files:
        try:
            with open(fpath, newline="") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    continue
                cols = {c.lower(): c for c in reader.fieldnames}
                user_col = next((cols[c] for c in user_cols if c in cols), None)
                if not user_col:
                    continue  # not an answers-shaped file
                start_col = next((cols[c] for c in start_cols if c in cols), None)
                end_col = next((cols[c] for c in end_cols if c in cols), None)
                date_col = next((cols[c] for c in single_date_cols if c in cols), None)
                scenario_col = next((cols[c] for c in scenario_cols if c in cols), None)

                for row in reader:
                    user = row.get(user_col, "").strip()
                    if not user:
                        continue
                    scenario = row.get(scenario_col, fpath.stem) if scenario_col else fpath.stem
                    try:
                        if start_col and end_col and row.get(start_col) and row.get(end_col):
                            start = parse_dt(row[start_col])
                            end = parse_dt(row[end_col])
                        elif date_col and row.get(date_col):
                            start = end = parse_dt(row[date_col])
                        else:
                            # user-level only, no date info -> flag entire history
                            start = datetime.min
                            end = datetime.max
                    except ValueError:
                        continue
                    windows.setdefault(user, []).append((start, end, str(scenario)))
                    loaded += 1
        except Exception as exc:
            print(f"WARNING: could not parse {fpath}: {exc}")

    print(f"Loaded {loaded} malicious-window record(s) covering {len(windows)} user(s) from {answers_dir}.")
    return windows


def is_malicious(username: str, ts: datetime, windows: dict):
    for start, end, scenario in windows.get(username, []):
        if start <= ts <= end:
            return True, scenario
    return False, None


# ============================================================
# Row -> ShadowKediEvent converters
# ============================================================

def _base_kwargs(prefix: str, row: dict, ts: datetime, is_anom: bool, scenario) -> dict:
    return dict(
        event_id=f"CERT-{prefix}-{row['id']}",
        timestamp=ts,
        agent_id=f"agent-{row['pc']}",
        hostname=row["pc"],
        username=row["user"],
        client_id=CLIENT_ID,
        source="cert_insider_threat",
        is_anomaly=is_anom,
        risk_reasons=([f"cert_insider_scenario:{scenario}"] if is_anom else []),
        risk_category=RiskCategory.CRITICAL if is_anom else RiskCategory.LOW,
        risk_score=90.0 if is_anom else 5.0,
        mitre_tags=(["T1052"] if is_anom else []),  # exfiltration-over-physical-medium as a coarse default
    )


def convert_logon_row(row: dict, windows: dict) -> ShadowKediEvent:
    ts = parse_dt(row["date"])
    is_anom, scenario = is_malicious(row["user"], ts, windows)
    kwargs = _base_kwargs("logon", row, ts, is_anom, scenario)
    kwargs["raw_data"] = {"activity": row.get("activity")}
    event = ShadowKediEvent(event_type=EventType.LOGIN_EVENT, **kwargs)
    return event


def convert_device_row(row: dict, windows: dict) -> ShadowKediEvent:
    ts = parse_dt(row["date"])
    is_anom, scenario = is_malicious(row["user"], ts, windows)
    kwargs = _base_kwargs("device", row, ts, is_anom, scenario)
    kwargs["raw_data"] = {"activity": row.get("activity")}
    event = ShadowKediEvent(event_type=EventType.USB_CONNECT, **kwargs)
    return event


def convert_file_row(row: dict, windows: dict, has_activity: bool, has_removable_flags: bool) -> ShadowKediEvent:
    ts = parse_dt(row["date"])
    is_anom, scenario = is_malicious(row["user"], ts, windows)

    if has_removable_flags:
        to_removable = _truthy(row.get("to_removable_media", ""))
        from_removable = _truthy(row.get("from_removable_media", ""))
    else:
        to_removable = from_removable = False  # signal unavailable in this schema variant

    activity = row.get("activity") if has_activity else None
    content = row.get("content", "") or ""
    content_len = len(content)  # length only — never store the licensed content text itself

    event_type = EventType.FILE_TRANSFER if (to_removable or from_removable) else EventType.FILE_ACCESS

    kwargs = _base_kwargs("file", row, ts, is_anom, scenario)
    kwargs["raw_data"] = {
        "activity": activity,
        "to_removable_media": to_removable,
        "from_removable_media": from_removable,
        "removable_media_flag_available": has_removable_flags,
        "content_length_chars": content_len,
    }
    filename = row.get("filename") or ""
    kwargs["file_name"] = filename or None
    kwargs["file_extension"] = ("." + filename.rsplit(".", 1)[-1]) if "." in filename else None
    kwargs["file_size_kb"] = round(content_len / 1024, 3) if content_len else None
    event = ShadowKediEvent(event_type=event_type, **kwargs)
    return event


def convert_http_row(row: dict, windows: dict, has_activity: bool, has_size: bool) -> ShadowKediEvent:
    ts = parse_dt(row["date"])
    is_anom, scenario = is_malicious(row["user"], ts, windows)

    activity_raw = row.get("activity") if has_activity else None
    activity = (activity_raw or "").lower()
    content = row.get("content", "") or ""
    url = row.get("url", "")

    inferred_reason = None
    if has_activity and "upload" in activity:
        event_type = EventType.CLOUD_UPLOAD
        inferred_label = "upload"
    elif has_activity and "download" in activity:
        event_type = EventType.FILE_TRANSFER
        inferred_label = "download"
    elif has_activity:
        event_type = EventType.BROWSER_ACTIVITY
        inferred_label = "browse"
    else:
        # real activity column missing — fall back to the keyword heuristic
        event_type, inferred_label, inferred_reason = infer_http_activity(url, content)

    if has_size:
        try:
            size = int(float(row.get("size", 0) or 0))
        except ValueError:
            size = 0
    else:
        size = len(content)  # length-of-content proxy, since no explicit size column exists

    kwargs = _base_kwargs("http", row, ts, is_anom, scenario)
    kwargs["raw_data"] = {
        "activity": activity_raw,
        "activity_available": has_activity,
        "url": url,
        "size_is_content_length_proxy": not has_size,
        "activity_inferred_method": "keyword_heuristic" if not has_activity else "reported",
        "activity_inferred_label": inferred_label,
        "activity_inferred_reason": inferred_reason,
    }
    kwargs["bytes_sent"] = size
    kwargs["destination_domain"] = domain_from_url(url)
    if inferred_reason and event_type != EventType.BROWSER_ACTIVITY:
        kwargs["risk_reasons"] = kwargs["risk_reasons"] + [f"heuristic_activity:{inferred_label}:{inferred_reason}"]
    event = ShadowKediEvent(event_type=event_type, **kwargs)
    return event


def convert_email_row(row: dict, windows: dict) -> ShadowKediEvent:
    ts = parse_dt(row["date"])
    is_anom, scenario = is_malicious(row["user"], ts, windows)
    to_addrs = row.get("to", "") or ""
    external = any(
        addr.strip() and not addr.strip().lower().endswith("@dtaa.com")  # r4.2's default internal domain
        for addr in to_addrs.split(";")
    )
    kwargs = _base_kwargs("email", row, ts, is_anom, scenario)
    kwargs["raw_data"] = {
        "activity": row.get("activity"),
        "to": to_addrs,
        "cc": row.get("cc"),
        "bcc": row.get("bcc"),
        "from": row.get("from"),
        "attachments": row.get("attachments"),
        "external_recipient": external,
    }
    try:
        size = int(float(row.get("size", 0) or 0))
    except ValueError:
        size = 0
    kwargs["bytes_sent"] = size
    if external:
        kwargs["risk_reasons"] = kwargs["risk_reasons"] + ["external_recipient"]
    event = ShadowKediEvent(event_type=EventType.NETWORK_CONN, **kwargs)
    return event


CONVERTERS = {
    "logon": lambda row, windows, **_: convert_logon_row(row, windows),
    "device": lambda row, windows, **_: convert_device_row(row, windows),
    "file": lambda row, windows, has_activity=False, has_removable_flags=False, **_: convert_file_row(
        row, windows, has_activity, has_removable_flags),
    "http": lambda row, windows, has_activity=False, has_size=False, **_: convert_http_row(
        row, windows, has_activity, has_size),
    "email": lambda row, windows, **_: convert_email_row(row, windows),
}


# ============================================================
# Psychometric (auxiliary, not events)
# ============================================================

def load_psychometric(data_dir: str) -> dict:
    """Returns {user_id: {"O":.., "C":.., "E":.., "A":.., "N":..}} if the
    file exists, else {}. Not converted to ShadowKediEvent — this is
    per-user trait data, not activity."""
    path = find_file(Path(data_dir), "psychometric.csv")
    if not path:
        return {}
    out = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        cols = {c.lower(): c for c in reader.fieldnames or []}
        user_col = cols.get("user_id") or cols.get("user")
        if not user_col:
            return {}
        for row in reader:
            uid = row.get(user_col)
            if not uid:
                continue
            out[uid] = {
                trait: row.get(cols.get(trait.lower(), trait))
                for trait in ("O", "C", "E", "A", "N")
                if cols.get(trait.lower())
            }
    return out


# ============================================================
# Main load pipeline
# ============================================================

def load_cert_dataset(data_dir: str, out_dir: str, answers_dir: str | None = None,
                       row_cap: int | None = DEFAULT_ROW_CAP, progress_every: int = 100_000):
    """
    Streams events straight to a JSON Lines file (one JSON object per line)
    as they're converted, instead of accumulating everything in memory first.
    This keeps peak memory bounded no matter how large the input is, and
    means progress already made survives even if a later file fails or the
    process gets interrupted — each file's rows are flushed to disk as soon
    as they're converted, not held until the very end.

    Returns a stats dict (counts only — not the events themselves).
    """
    ddir = Path(data_dir)
    if not ddir.exists():
        raise FileNotFoundError(f"--data-dir {data_dir} does not exist")

    out_path = Path(out_dir) / "cert_events.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    windows = load_malicious_windows(answers_dir)

    stats = {"total": 0, "anomalous": 0, "by_event_type": {}}

    with open(out_path, "w") as out_f:
        for key, filename in CORE_FILES.items():
            fpath = find_file(ddir, filename)
            if not fpath:
                print(f"SKIP: {filename} not found in {data_dir}")
                continue

            converter = CONVERTERS[key]
            n_read = 0
            n_ok = 0
            n_failed = 0
            with open(fpath, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                available_cols = set(c.lower() for c in (reader.fieldnames or []))
                col_flags = {
                    "has_activity": "activity" in available_cols,
                    "has_removable_flags": "to_removable_media" in available_cols or "from_removable_media" in available_cols,
                    "has_size": "size" in available_cols,
                }
                missing = []
                if key == "file" and not col_flags["has_removable_flags"]:
                    missing.append("to_removable_media/from_removable_media (exfiltration-via-USB signal unavailable — will default to FILE_ACCESS)")
                if key == "http" and not col_flags["has_activity"]:
                    missing.append("activity (upload/download can't be distinguished — will default to BROWSER_ACTIVITY)")
                if key == "http" and not col_flags["has_size"]:
                    missing.append("size (using content-length as a proxy instead)")
                if missing:
                    print(f"  NOTE: {filename} is missing expected column(s): {'; '.join(missing)}")

                for row in reader:
                    if row_cap is not None and n_read >= row_cap:
                        print(f"  {filename}: row cap ({row_cap}) reached, stopping early. Use --full to disable.")
                        break
                    n_read += 1
                    try:
                        event = converter(row, windows, **col_flags)
                        out_f.write(event.model_dump_json())
                        out_f.write("\n")
                        n_ok += 1
                        stats["total"] += 1
                        if event.is_anomaly:
                            stats["anomalous"] += 1
                        et = event.event_type.value
                        stats["by_event_type"][et] = stats["by_event_type"].get(et, 0) + 1
                        if n_ok % progress_every == 0:
                            print(f"    ... {filename}: {n_ok} rows converted and written so far")
                    except Exception as exc:
                        n_failed += 1
                        if n_failed <= 5:
                            print(f"  WARNING: failed to convert a row in {filename}: {exc}")
            out_f.flush()
            print(f"{filename}: read {n_read}, converted {n_ok}, failed {n_failed}  (flushed to disk)")

    return stats, out_path


def main():
    parser = argparse.ArgumentParser(description="Convert CERT r4.2 insider-threat logs into ShadowKediEvent records.")
    parser.add_argument("--data-dir", default="data/raw/cert", help="Directory containing logon.csv, device.csv, file.csv, http.csv, email.csv")
    parser.add_argument("--answers-dir", default=None, help="Optional directory with malicious-insider ground truth CSVs")
    parser.add_argument("--out", default="data/synthetic", help="Output directory")
    parser.add_argument("--limit-per-file", type=int, default=DEFAULT_ROW_CAP, help=f"Row cap per input file (default {DEFAULT_ROW_CAP})")
    parser.add_argument("--full", action="store_true", help="Disable the row cap and load everything (can be several million rows)")
    args = parser.parse_args()

    row_cap = None if args.full else args.limit_per_file

    print(f"Loading CERT r4.2 data from {args.data_dir} (row cap per file: {row_cap or 'none'}) ...")
    print("Streaming output to disk as each file is processed (low, bounded memory use) ...")
    stats, out_path = load_cert_dataset(args.data_dir, args.out, answers_dir=args.answers_dir, row_cap=row_cap)

    print(f"\nTotal converted: {stats['total']} events")
    print(f"Saved to: {out_path}  (JSON Lines format — one event per line)")
    print(f"Anomalous (malicious-insider) events: {stats['anomalous']} ({stats['anomalous'] / max(stats['total'],1) * 100:.3f}%)")
    print(f"Event type breakdown: {stats['by_event_type']}")


if __name__ == "__main__":
    main()
