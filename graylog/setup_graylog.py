#!/usr/bin/env python3
"""Graylog side of snipe-it-audit-log-exporter: index set, stream, exclusions.

Creates (if missing) a dedicated index set and a "snipe-it" stream that takes
every message with application == snipe-it out of the Default Stream. If a
catch-all stream already claims everything from your GELF input (for example
one stream per input), pass it with --exclude-from and it gets an inverted
application == snipe-it rule, so the audit log is not stored twice.

No pipeline is needed: the exporter sends every field ready to search.

--alerts also creates five security alerts (privilege, account and login
changes, API-token use, changes from public IPs); see README.md.

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


# Security alerts only: Snipe-IT does its own asset alerting (expiring licenses,
# audits due, ...). `timestamp` is the action's own time and the exporter polls
# every POLL_INTERVAL (60 s), so ingest lag is about a minute; the window leaves
# room for an outage. Grace must exceed the window, or an event still inside the
# window would notify again on the next run. A backfill never fires: its events
# are old.
ALERT_WINDOW_MS = 1_800_000      # 30 min
ALERT_EVERY_MS = 300_000         # 5 min
ALERT_GRACE_MS = 2_100_000       # 35 min = window + one interval
# remote_ip is a keyword field (no CIDR queries), so: trailing wildcards
PRIVATE_IPS = " OR ".join(["10.*", "192.168.*", "127.*"] + [f"172.{n}.*" for n in range(16, 32)])


def alert_specs(api_exclude):
    api_query = "action_source:api" + (f" AND NOT ({api_exclude})" if api_exclude else "")
    # (title, query, priority, group_by, description). Graylog's email template
    # prints only group-by fields, so the who/whom fields are part of the key:
    # one notification per affected account, not one per burst.
    return [
        ("user privileges changed", "snipeit_security:user_privileges", 3,
         ["item_name", "admin_name", "changed_fields"],
         "A user's permissions (superuser/admin/per-area flags) or Groups changed. "
         "item_name = the user changed, admin_name = who did it."),
        ("user account created, deleted or restored", "snipeit_security:user_lifecycle", 2,
         ["action_type", "item_name", "admin_name"],
         "A Snipe-IT user account was created, deleted or restored."),
        ("user login identity changed", "snipeit_security:user_identity", 2,
         ["item_name", "admin_name", "changed_fields"],
         "username, email, password or activated changed (a change that also touches "
         "permissions/Groups goes to the privileges alert instead)."),
        ("change made through an API token", api_query, 3,
         ["admin_name", "user_agent", "action_type", "item_type"],
         "A change was made with an API token: admin_name = whose token, user_agent = the "
         "client. Exclude known automation with --api-token-exclude."),
        ("change from a non-internal IP", f"_exists_:remote_ip AND NOT remote_ip:({PRIVATE_IPS})", 3,
         ["remote_ip", "admin_name", "action_type"],
         "A change came from a public IP address (not RFC1918). Needs Snipe-IT to see real "
         "client IPs (trusted proxy configured)."),
    ]


def alert_definition(title, query, priority, group_by, description, stream_id, notification_id):
    return {
        "title": title,
        "description": description,
        "remediation_steps": "",
        "priority": priority,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": query,
            "query_parameters": [],
            "filters": [],
            "streams": [stream_id],
            "stream_categories": [],
            "group_by": group_by,
            "series": [{"type": "count", "id": "count-0", "field": group_by[0]}],
            "conditions": {"expression": {
                "expr": ">",
                "left": {"expr": "number-ref", "ref": "count-0"},
                "right": {"expr": "number", "value": 0.0}}},
            "search_within_ms": ALERT_WINDOW_MS,
            "execute_every_ms": ALERT_EVERY_MS,
            "use_cron_scheduling": False,
            "cron_expression": None,
            "cron_timezone": None,
            "event_limit": 100,
        },
        "field_spec": {
            # required only for group_by[0]: admin_name is missing on end-user actions,
            # and a required missing field would drop the event instead of "(Empty Value)"
            g: {"data_type": "string",
                "providers": [{"type": "template-v1", "template": "${source." + g + "}",
                               "require_values": g == group_by[0]}]}
            for g in group_by
        },
        "key_spec": group_by,
        "notification_settings": {"grace_period_ms": ALERT_GRACE_MS, "backlog_size": 10},
        "notifications": ([{"notification_id": notification_id, "notification_parameters": None}]
                          if notification_id else []),
        "storage": [{"type": "persist-to-streams-v1", "streams": ["000000000000000000000002"]}],
        "state": "ENABLED",
    }


# fields compared to decide whether an existing definition needs an update
def _alert_fingerprint(d):
    c = d["config"]
    return (d["priority"], c["query"], c["streams"], c["group_by"], c["search_within_ms"],
            c["execute_every_ms"], d["notification_settings"]["grace_period_ms"],
            sorted(n["notification_id"] for n in d.get("notifications", [])))


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

    def notification_id(self):
        title = self.args.notification
        if not title:
            return None
        found = self.gl.get("/api/events/notifications?per_page=500")
        for n in found.get("notifications", found.get("elements", [])):
            if n["title"] == title:
                return n["id"]
        sys.exit(f"--notification: no event notification titled {title!r}")

    def alerts(self, stream_id):
        nid = self.notification_id()
        if not nid:
            print("note  no --notification: alerts create events but send nothing")
        have = self.gl.get("/api/events/definitions?per_page=500")
        have = {d["title"]: d for d in have.get("event_definitions", have.get("elements", []))}
        for spec in alert_specs(self.args.api_token_exclude):
            title = f"{self.args.alert_prefix} - {spec[0]}"
            want = alert_definition(title, *spec[1:], stream_id or "0" * 24, nid)
            cur = have.get(title)
            if not stream_id:  # dry run before the stream exists
                self.step(f"create alert {title!r}")
                continue
            check = dict(want, id=cur["id"] if cur else "0" * 24)
            v = self.gl.post("/api/events/definitions/validate", check)
            if v.get("errors") or v.get("failed"):
                sys.exit(f"alert {title!r} does not validate: {v}")
            if cur and _alert_fingerprint(cur) == _alert_fingerprint(want):
                print(f"ok    alert {title!r}")
            elif cur:
                if self.step(f"update alert {title!r}"):
                    self.gl.req("PUT", f"/api/events/definitions/{cur['id']}", dict(want, id=cur["id"]))
            elif self.step(f"create alert {title!r}"):
                self.gl.post("/api/events/definitions", {"entity": want})

    def run(self):
        print(f"target {self.gl.url}")
        isid = self.index_set()
        streams = self.gl.get("/api/streams")["streams"]
        sid = self.stream(isid, streams)
        for title in self.args.exclude_from:
            self.exclude_from(title, streams)
        if self.args.alerts:
            self.alerts(sid)
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
    p.add_argument("--alerts", action="store_true", help="also create the security alerts (event definitions)")
    p.add_argument("--notification", metavar="TITLE",
                   help="existing event notification (e.g. an email notification) the alerts send to")
    p.add_argument("--api-token-exclude", metavar="QUERY", default="",
                   help="known API automation to ignore, e.g. 'item_type:license'")
    p.add_argument("--alert-prefix", default="Snipe-IT", help="alert title prefix (default: %(default)s)")
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
