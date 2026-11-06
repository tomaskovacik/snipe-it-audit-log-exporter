#!/usr/bin/env python3
"""Graylog side of snipe-it-audit-log-exporter: index set, stream, exclusions.

Creates (if missing) a dedicated index set and a "snipe-it" stream that takes
every message with application == snipe-it out of the Default Stream. If a
catch-all stream already claims everything from your GELF input (for example
one stream per input), pass it with --exclude-from and it gets an inverted
application == snipe-it rule, so the audit log is not stored twice.

No pipeline is needed: the exporter sends every field ready to search.

Reconciles by title, so re-running is safe. Without --apply it only prints
what it would do.

    export GRAYLOG_URL=https://graylog.example.com:9000
    export GRAYLOG_API_TOKEN=...            # or GRAYLOG_API_TOKEN_FILE=/path/to/token
    python3 setup_graylog.py                         # dry run
    python3 setup_graylog.py --exclude-from GELF-TCP --apply

The token needs permission to create index sets and streams (an admin token
is simplest). Tested against Graylog 7.2.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request


def env(name, default=None):
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name, default)


class Graylog:
    def __init__(self, url, token, verify_tls=True):
        self.url = url.rstrip("/")
        self.auth = base64.b64encode(f"{token}:token".encode()).decode()
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Basic {self.auth}", "X-Requested-By": "snipeit-setup",
            "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=60, context=self.ctx) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as exc:
            sys.exit(f"{method} {path} failed: HTTP {exc.code} {exc.read().decode()[:400]}")
        return json.loads(raw) if raw.strip() else {}

    def get(self, path):
        return self.req("GET", path)

    def post(self, path, body=None):
        return self.req("POST", path, body)


def index_set_body(args):
    lifetime = {"index_lifetime_min": args.lifetime_min, "index_lifetime_max": args.lifetime_max}
    return {
        "title": args.index_set,
        "description": "Snipe-IT audit log (action_logs) via snipe-it-audit-log-exporter",
        "index_prefix": args.index_prefix,
        "shards": 1,
        "replicas": 0,
        "index_analyzer": "standard",
        "index_optimization_max_num_segments": 1,
        "index_optimization_disabled": False,
        "field_type_refresh_interval": 5000,
        "use_legacy_rotation": False,
        "data_tiering": dict(lifetime, type="hot_only"),
        "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategy",
        "rotation_strategy": dict(lifetime, type="org.graylog2.indexer.rotation.strategies."
                                                 "TimeBasedSizeOptimizingStrategyConfig"),
        "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
        "retention_strategy": {"type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
                               "max_number_of_indices": 20},
        "writable": True,
    }


class Setup:
    def __init__(self, gl, args):
        self.gl = gl
        self.args = args
        # type 1 = "match exactly"
        self.match = {"field": "application", "type": 1, "value": args.application}

    def step(self, what):
        print(("APPLY " if self.args.apply else "WOULD ") + what)
        return self.args.apply

    def index_set(self):
        for x in self.gl.get("/api/system/indices/index_sets")["index_sets"]:
            if x["title"] == self.args.index_set:
                print(f"ok    index set {x['id']} ({x['index_prefix']})")
                return x["id"]
        if not self.step(f"create index set {self.args.index_set} (prefix {self.args.index_prefix}, "
                         f"keep {self.args.lifetime_min}-{self.args.lifetime_max})"):
            return None
        return self.gl.post("/api/system/indices/index_sets", index_set_body(self.args))["id"]

    def stream(self, index_set_id, streams):
        title = self.args.stream
        s = next((s for s in streams if s["title"] == title), None)
        if s:
            print(f"ok    stream {s['id']} rules={[(r['field'], r['value']) for r in s['rules']]}")
            if s["disabled"] and self.step("resume stream"):
                self.gl.post(f"/api/streams/{s['id']}/resume")
            return s["id"]
        if not self.step(f"create stream {title} ({self.match['field']} == {self.match['value']})"):
            return None
        body = {"entity": {
            "title": title,
            "description": f"Snipe-IT audit log (GELF, _application={self.match['value']})",
            "index_set_id": index_set_id,
            "matching_type": "AND",
            "remove_matches_from_default_stream": True,
            "rules": [dict(self.match, inverted=False, description="snipe-it-audit-log-exporter")],
        }, "share_request": None}
        sid = self.gl.post("/api/streams", body)["stream_id"]
        self.gl.post(f"/api/streams/{sid}/resume")  # API-created streams start paused
        return sid

    def exclude_from(self, title, streams):
        s = next((s for s in streams if s["title"] == title), None)
        if not s:
            sys.exit(f"--exclude-from: no stream titled {title!r}")
        m = self.match
        if any(r["field"] == m["field"] and r["value"] == m["value"] and r["inverted"] for r in s["rules"]):
            print(f"ok    {title} already excludes {m['value']}")
            return
        if s.get("matching_type") == "OR":
            # an inverted rule in an OR stream would match nearly everything
            sys.exit(f"--exclude-from: {title!r} matches ANY rule (OR); exclude manually")
        if self.step(f"add inverted rule {m['field']} == {m['value']} to {title} {s['id']}"):
            self.gl.post(f"/api/streams/{s['id']}/rules",
                         dict(m, inverted=True, description="snipe-it has its own stream"))

    def run(self):
        print(f"target {self.gl.url}")
        isid = self.index_set()
        streams = self.gl.get("/api/streams")["streams"]
        sid = self.stream(isid, streams)
        for title in self.args.exclude_from:
            self.exclude_from(title, streams)
        if sid:
            print(json.dumps({"index_set": isid, "stream": sid}))


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--apply", action="store_true", help="make the changes (default: dry run)")
    p.add_argument("--exclude-from", action="append", default=[], metavar="STREAM",
                   help="catch-all stream that must not keep snipe-it messages (repeatable)")
    p.add_argument("--stream", default="snipe-it", help="stream title (default: %(default)s)")
    p.add_argument("--index-set", default="snipe-it", help="index set title (default: %(default)s)")
    p.add_argument("--index-prefix", default="snipeit", help="index prefix (default: %(default)s)")
    p.add_argument("--application", default="snipe-it",
                   help="value of the exporter's _application field (default: %(default)s)")
    p.add_argument("--lifetime-min", default="P365D", help="minimum retention, ISO 8601 (default: %(default)s)")
    p.add_argument("--lifetime-max", default="P1095D", help="maximum retention, ISO 8601 (default: %(default)s)")
    p.add_argument("--insecure", action="store_true", help="do not verify the Graylog TLS certificate")
    args = p.parse_args()

    token = env("GRAYLOG_API_TOKEN")
    if not token:
        sys.exit("set GRAYLOG_API_TOKEN (or GRAYLOG_API_TOKEN_FILE)")
    verify = not args.insecure
    gl = Graylog(env("GRAYLOG_URL", "http://localhost:9000"), token, verify)
    Setup(gl, args).run()


if __name__ == "__main__":
    main()
