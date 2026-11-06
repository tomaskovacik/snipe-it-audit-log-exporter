#!/usr/bin/env python3
"""Snipe-IT audit log (action_logs) -> Graylog GELF exporter.

Polls GET /api/v1/reports/activity and ships every new entry to Graylog
as a GELF message. Progress is checkpointed in a small JSON state file so
restarts neither lose nor (mostly) duplicate events. Delivery is
at-least-once; every message carries `_snipeit_log_id` for de-duplication.

Two phases:
  * backfill - history is walked oldest-first (sort=id&order=asc) with
    offset paging, checkpointing after each page.
  * tail     - each poll walks newest-first (order=desc) until it reaches
    an id that was already exported. This is robust against rows being
    deleted, because it never relies on a stored offset.
"""

import datetime as dt
import html
import http.client
import json
import logging
import os
import random
import re
import signal
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from zoneinfo import ZoneInfo

log = logging.getLogger("snipeit-exporter")


# --------------------------------------------------------------------------- config

def env(name, default=None, required=False):
    value = os.environ.get(name)
    file_path = os.environ.get(name + "_FILE")
    if file_path:
        with open(file_path, encoding="utf-8") as fh:
            value = fh.read().strip()
    if value in (None, ""):
        if required:
            sys.exit(f"missing required environment variable {name} (or {name}_FILE)")
        return default
    return value


def env_bool(name, default):
    return str(env(name, str(default))).lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self):
        self.snipeit_url = env("SNIPEIT_URL", required=True).rstrip("/")
        self.snipeit_token = env("SNIPEIT_API_TOKEN", required=True)
        self.snipeit_verify_tls = env_bool("SNIPEIT_VERIFY_TLS", True)
        self.snipeit_timezone = ZoneInfo(env("SNIPEIT_TIMEZONE", "UTC"))
        self.page_size = int(env("PAGE_SIZE", "500"))
        self.poll_interval = float(env("POLL_INTERVAL", "60"))
        self.request_delay = float(env("REQUEST_DELAY", "0.6"))  # stay under 120 req/min
        self.start_from = env("START_FROM", "beginning").lower()  # beginning | now
        # ids are allocated before commit, so a lower id can become visible after a
        # higher one; re-check this many ids below the cursor on every poll
        self.lookback_ids = int(env("LOOKBACK_IDS", "100"))
        self.state_file = env("STATE_FILE", "/data/state.json")
        self.health_file = env("HEALTH_FILE", "/tmp/exporter-healthy")

        self.output = env("OUTPUT", "gelf").lower()  # gelf | stdout
        self.graylog_host = env("GRAYLOG_HOST", "graylog")
        self.graylog_port = int(env("GRAYLOG_PORT", "12201"))
        self.graylog_protocol = env("GRAYLOG_PROTOCOL", "tcp").lower()  # tcp | udp | http
        self.graylog_tls = env_bool("GRAYLOG_TLS", False)
        self.graylog_verify_tls = env_bool("GRAYLOG_VERIFY_TLS", True)
        self.graylog_http_path = env("GRAYLOG_HTTP_PATH", "/gelf")
        self.gelf_source = env("GELF_SOURCE", urllib.parse.urlparse(self.snipeit_url).hostname or "snipe-it")
        self.gelf_udp_chunk_size = int(env("GELF_UDP_CHUNK_SIZE", "1420"))
        self.gelf_extra_fields = json.loads(env("GELF_EXTRA_FIELDS", "{}"))
        self.include_raw = env_bool("GELF_INCLUDE_RAW", True)

        if self.start_from not in ("beginning", "now"):
            sys.exit("START_FROM must be 'beginning' or 'now'")
        if self.output not in ("gelf", "stdout"):
            sys.exit("OUTPUT must be 'gelf' or 'stdout'")
        if self.graylog_protocol not in ("tcp", "udp", "http"):
            sys.exit("GRAYLOG_PROTOCOL must be tcp, udp or http")


# --------------------------------------------------------------------------- state

class State:
    """{"last_id": int|None, "phase": "backfill"|"tail", "backfill_offset": int,
        "recent_ids": [ids already exported inside the lookback window]}"""

    def __init__(self, path):
        self.path = path
        self.last_id = None
        self.phase = None
        self.backfill_offset = 0
        self.recent_ids = set()
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.last_id = data.get("last_id")
            self.phase = data.get("phase")
            self.backfill_offset = int(data.get("backfill_offset", 0))
            self.recent_ids = set(data.get("recent_ids", []))
            log.info("loaded state last_id=%s phase=%s", self.last_id, self.phase)
        except FileNotFoundError:
            log.info("no state file at %s, starting fresh", path)

    def save(self):
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"last_id": self.last_id, "phase": self.phase,
                       "backfill_offset": self.backfill_offset,
                       "recent_ids": sorted(self.recent_ids)}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------- snipe-it client

class SnipeItError(Exception):
    pass


class SnipeIt:
    def __init__(self, cfg):
        self.cfg = cfg
        self.ctx = ssl.create_default_context()
        if not cfg.snipeit_verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self._last_request = 0.0

    def activity(self, offset, limit, order):
        params = {"sort": "id", "order": order, "offset": offset, "limit": limit}
        url = f"{self.cfg.snipeit_url}/api/v1/reports/activity?{urllib.parse.urlencode(params)}"
        for attempt in range(8):
            wait = self.cfg.request_delay - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {self.cfg.snipeit_token}",
                "Accept": "application/json",
                "User-Agent": "snipeit-audit-log-exporter/1.0",
            })
            try:
                with urllib.request.urlopen(req, timeout=60, context=self.ctx) as resp:
                    body = json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code == 429 or exc.code >= 500:
                    delay = float(exc.headers.get("Retry-After") or min(60, 2 ** attempt))
                    log.warning("snipe-it HTTP %s, retrying in %.0fs", exc.code, delay)
                    time.sleep(delay)
                    continue
                raise SnipeItError(f"HTTP {exc.code}: {exc.read()[:300]!r}") from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                delay = min(60, 2 ** attempt)
                log.warning("snipe-it request failed (%s), retrying in %.0fs", exc, delay)
                time.sleep(delay)
                continue
            if isinstance(body, dict) and body.get("status") == "error":
                raise SnipeItError(f"API error: {body.get('messages')}")
            return body.get("total", 0), body.get("rows", [])
        raise SnipeItError("giving up after repeated failures")


# --------------------------------------------------------------------------- GELF mapping

def _u(value):
    """Snipe-IT HTML-escapes strings in API output; undo that."""
    return html.unescape(value) if isinstance(value, str) else value


def _dt(obj):
    if isinstance(obj, dict):
        return obj.get("datetime")
    return obj


def parse_timestamp(value, tz):
    if not value:
        return time.time()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=tz).timestamp()
        except ValueError:
            continue
    return time.time()


# Snipe-IT occasionally stores a zero/epoch created_at (e.g. some bulk checkins)
MIN_VALID_TIMESTAMP = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc).timestamp()


def event_timestamp(row, tz):
    """created_at, or updated_at when created_at is obviously bogus."""
    ts = parse_timestamp(_dt(row.get("created_at")), tz)
    if ts >= MIN_VALID_TIMESTAMP:
        return ts, False
    fallback = parse_timestamp(_dt(row.get("updated_at")), tz)
    return (fallback if fallback >= MIN_VALID_TIMESTAMP else time.time()), True


def changed_field_name(key):
    """log_meta key -> GELF field: 'Status Label' -> changed_status_label."""
    return "changed_" + re.sub(r"[^0-9A-Za-z]+", "_", key).strip("_").lower()


# GELF only carries strings and numbers (Graylog stringifies a list), and a
# comma-joined keyword can't be searched for one name without a leading
# wildcard - so every changed field also gets its own _changed_<name>=1 flag.
PRIVILEGE_FIELDS = {"permissions", "Groups"}
IDENTITY_FIELDS = {"username", "email", "password", "activated"}


def security_class(action, item_type, changed):
    if item_type == "user":
        if action in ("create new", "delete", "restore"):
            return "user_lifecycle"
        if action == "update" and changed & PRIVILEGE_FIELDS:
            return "user_privileges"
        if action == "update" and changed & IDENTITY_FIELDS:
            return "user_identity"
    elif action == "delete":
        return "item_deleted"
    return None


def to_gelf(row, cfg):
    item = row.get("item") or {}
    target = row.get("target") or {}
    admin = row.get("created_by") or row.get("admin") or {}
    location = row.get("location") or {}
    action = _u(row.get("action_type")) or "unknown"

    parts = [_u(admin.get("name")) or "system", action]
    if item:
        parts.append(f"{_u(item.get('type'))} '{_u(item.get('name'))}'")
    if target:
        parts.append(f"-> {_u(target.get('type'))} '{_u(target.get('name'))}'")

    timestamp, ts_fixed = event_timestamp(row, cfg.snipeit_timezone)
    msg = {
        "version": "1.1",
        "host": cfg.gelf_source,
        "short_message": " ".join(p for p in parts if p),
        "timestamp": round(timestamp, 3),
        "level": 6,
        "_application": "snipe-it",
        "_event_type": "audit",
        "_snipeit_log_id": row.get("id"),
        "_action_type": action,
        "_action_source": _u(row.get("action_source")),
        "_action_date": _dt(row.get("action_date")),
        "_item_type": _u(item.get("type")),
        "_item_id": item.get("id"),
        "_item_name": _u(item.get("name")),
        "_item_serial": _u(item.get("serial")),
        "_target_type": _u(target.get("type")),
        "_target_id": target.get("id"),
        "_target_name": _u(target.get("name")),
        "_admin_id": admin.get("id"),
        "_admin_name": _u(admin.get("name")),
        "_location_id": location.get("id"),
        "_location_name": _u(location.get("name")),
        "_quantity": row.get("quantity"),
        "_order_number": _u(row.get("order_number")),
        "_note": _u(row.get("note")),
        "_remote_ip": _u(row.get("remote_ip")),
        "_user_agent": _u(row.get("user_agent")),
    }
    if ts_fixed:
        msg["_created_at_raw"] = _dt(row.get("created_at"))
        msg["_timestamp_fallback"] = "updated_at"
    meta = row.get("log_meta")
    changed = set(meta) if isinstance(meta, dict) else set()
    if meta:
        msg["_changed_fields"] = ",".join(meta.keys()) if isinstance(meta, dict) else None
        msg["_log_meta"] = json.dumps(meta, ensure_ascii=False)
    for key in changed:
        name = changed_field_name(key)
        if name not in ("changed_", "changed_fields"):
            msg["_" + name] = 1
    msg["_snipeit_security"] = security_class(action, _u(item.get("type")), changed)
    if cfg.include_raw:
        msg["full_message"] = json.dumps(row, ensure_ascii=False)
    for key, value in cfg.gelf_extra_fields.items():
        msg["_" + key.lstrip("_")] = value
    return {k: v for k, v in msg.items() if v not in (None, "")}


# --------------------------------------------------------------------------- outputs

class StdoutOutput:
    def send(self, msg):
        sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")

    def flush(self):
        sys.stdout.flush()


class GelfTcp:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sock = None

    def _connect(self):
        sock = socket.create_connection((self.cfg.graylog_host, self.cfg.graylog_port), timeout=30)
        if self.cfg.graylog_tls:
            ctx = ssl.create_default_context()
            if not self.cfg.graylog_verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.cfg.graylog_host)
        self.sock = sock

    def send(self, msg):
        data = json.dumps(msg, ensure_ascii=False).encode() + b"\0"
        if self.sock is None:
            self._connect()
        try:
            self.sock.sendall(data)
        except OSError:
            self.close()
            raise

    def flush(self):
        pass

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None


class GelfUdp:
    MAX_CHUNKS = 128

    def __init__(self, cfg):
        self.addr = (cfg.graylog_host, cfg.graylog_port)
        self.chunk = cfg.gelf_udp_chunk_size
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg):
        data = zlib.compress(json.dumps(msg, ensure_ascii=False).encode())
        if len(data) <= self.chunk:
            self.sock.sendto(data, self.addr)
            return
        size = self.chunk - 12
        chunks = [data[i:i + size] for i in range(0, len(data), size)]
        if len(chunks) > self.MAX_CHUNKS:
            log.error("dropping GELF message %s: too large for UDP (%d bytes)",
                      msg.get("_snipeit_log_id"), len(data))
            return
        msg_id = random.getrandbits(64).to_bytes(8, "big")
        for seq, chunk in enumerate(chunks):
            self.sock.sendto(b"\x1e\x0f" + msg_id + struct.pack("BB", seq, len(chunks)) + chunk, self.addr)

    def flush(self):
        pass


class GelfHttp:
    def __init__(self, cfg):
        self.cfg = cfg
        self.conn = None

    def _connect(self):
        if self.cfg.graylog_tls:
            ctx = ssl.create_default_context()
            if not self.cfg.graylog_verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.conn = http.client.HTTPSConnection(self.cfg.graylog_host, self.cfg.graylog_port,
                                                    timeout=30, context=ctx)
        else:
            self.conn = http.client.HTTPConnection(self.cfg.graylog_host, self.cfg.graylog_port, timeout=30)

    def send(self, msg):
        body = zlib.compress(json.dumps(msg, ensure_ascii=False).encode())
        for attempt in (1, 2):  # one silent retry for stale keep-alive connections
            if self.conn is None:
                self._connect()
            try:
                self.conn.request("POST", self.cfg.graylog_http_path, body=body, headers={
                    "Content-Type": "application/json", "Content-Encoding": "deflate"})
                resp = self.conn.getresponse()
                resp.read()
                if resp.status not in (200, 202, 204):
                    raise OSError(f"graylog GELF HTTP returned {resp.status}")
                return
            except (OSError, http.client.HTTPException):
                self.conn.close()
                self.conn = None
                if attempt == 2:
                    raise

    def flush(self):
        pass


def make_output(cfg):
    if cfg.output == "stdout":
        return StdoutOutput()
    return {"tcp": GelfTcp, "udp": GelfUdp, "http": GelfHttp}[cfg.graylog_protocol](cfg)


# --------------------------------------------------------------------------- exporter

class Exporter:
    def __init__(self, cfg, api=None, output=None, state=None):
        self.cfg = cfg
        self.api = api or SnipeIt(cfg)
        self.output = output or make_output(cfg)
        self.state = state or State(cfg.state_file)

    def heartbeat(self):
        try:
            with open(self.cfg.health_file, "w", encoding="utf-8") as fh:
                fh.write(str(time.time()))
        except OSError as exc:
            log.warning("cannot write health file: %s", exc)

    def _ship(self, rows):
        for row in rows:
            self.output.send(to_gelf(row, self.cfg))
        self.output.flush()

    def initialise(self):
        if self.state.phase:
            return
        if self.cfg.start_from == "now":
            _, rows = self.api.activity(0, 1, "desc")
            self.state.last_id = rows[0]["id"] if rows else 0
            # treat everything up to now as exported, including the lookback window
            self.state.recent_ids = set(range(max(1, self.state.last_id - self.cfg.lookback_ids + 1),
                                              self.state.last_id + 1))
            self.state.phase = "tail"
            log.info("START_FROM=now: skipping history, starting after id %s", self.state.last_id)
        else:
            self.state.phase = "backfill"
            self.state.backfill_offset = 0
            self.state.last_id = 0
        self.state.save()

    def backfill(self):
        """Oldest-first walk over the whole history, checkpointed per page."""
        sent = 0
        while True:
            total, rows = self.api.activity(self.state.backfill_offset, self.cfg.page_size, "asc")
            fresh = [r for r in rows if r["id"] > (self.state.last_id or 0)]
            self._ship(fresh)
            sent += len(fresh)
            if rows:
                self.state.last_id = max(self.state.last_id or 0, max(r["id"] for r in rows))
                floor = self.state.last_id - self.cfg.lookback_ids
                self.state.recent_ids = {i for i in self.state.recent_ids | {r["id"] for r in fresh}
                                         if i > floor}
            self.state.backfill_offset += len(rows)
            done = len(rows) < self.cfg.page_size
            if done:
                self.state.phase = "tail"
            self.state.save()
            self.heartbeat()
            log.info("backfill: %d/%d processed (last_id=%s)", self.state.backfill_offset, total,
                     self.state.last_id)
            if done:
                return sent

    def tail(self):
        """Newest-first walk until we are below the lookback window."""
        last_id = self.state.last_id or 0
        floor = max(0, last_id - self.cfg.lookback_ids)
        known = {i for i in self.state.recent_ids if i > floor}
        offset, newest, seen, sent = 0, last_id, set(), 0
        while True:
            _, rows = self.api.activity(offset, self.cfg.page_size, "desc")
            fresh = [r for r in rows if r["id"] > floor and r["id"] not in known and r["id"] not in seen]
            late = [r["id"] for r in fresh if r["id"] <= last_id]
            if late:
                log.info("picked up late-committed id(s) %s", late)
            # Pages are shipped immediately to bound memory; the checkpoint is only
            # advanced once the whole gap is covered, so a crash means re-sending
            # (duplicates), never skipping.
            self._ship(fresh)
            sent += len(fresh)
            seen.update(r["id"] for r in fresh)
            if fresh:
                newest = max(newest, max(r["id"] for r in fresh))
            if len(rows) < self.cfg.page_size or any(r["id"] <= floor for r in rows):
                break
            offset += len(rows)
        if seen:
            self.state.last_id = newest
            new_floor = max(0, newest - self.cfg.lookback_ids)
            self.state.recent_ids = {i for i in known | seen if i > new_floor}
            self.state.save()
        return sent

    def poll_once(self):
        self.initialise()
        if self.state.phase == "backfill":
            return self.backfill()
        return self.tail()

    def run(self):
        stop = {"flag": False}

        def _stop(signum, _frame):
            log.info("received signal %s, stopping", signum)
            stop["flag"] = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        log.info("exporting %s -> %s", self.cfg.snipeit_url,
                 "stdout" if self.cfg.output == "stdout" else
                 f"gelf+{self.cfg.graylog_protocol}://{self.cfg.graylog_host}:{self.cfg.graylog_port}")

        while not stop["flag"]:
            started = time.monotonic()
            try:
                sent = self.poll_once()
                if sent:
                    log.info("shipped %d event(s), last_id=%s", sent, self.state.last_id)
                else:
                    log.debug("no new events")
                self.heartbeat()
            except Exception:  # keep the daemon alive, retry from last checkpoint
                log.exception("poll failed, will retry")
            remaining = self.cfg.poll_interval - (time.monotonic() - started)
            while remaining > 0 and not stop["flag"]:
                time.sleep(min(1.0, remaining))
                remaining -= 1.0


def healthcheck():
    cfg_interval = float(os.environ.get("POLL_INTERVAL", "60"))
    path = os.environ.get("HEALTH_FILE", "/tmp/exporter-healthy")
    try:
        age = time.time() - os.path.getmtime(path)
    except OSError:
        return 1
    # backfill of a large history can take a while; be generous
    return 0 if age < max(300, cfg_interval * 5) else 1


def main():
    if "--healthcheck" in sys.argv:
        sys.exit(healthcheck())
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        stream=sys.stderr)
    cfg = Config()
    exporter = Exporter(cfg)
    if "--once" in sys.argv:
        exporter.initialise()
        while exporter.state.phase == "backfill":
            exporter.backfill()
        log.info("shipped %d event(s)", exporter.tail())
        return
    exporter.run()


if __name__ == "__main__":
    main()
