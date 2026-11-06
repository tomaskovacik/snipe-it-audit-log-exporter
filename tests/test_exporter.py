import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as HTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import exporter  # noqa: E402


def row(i, action="checkout"):
    return {
        "id": i,
        "action_type": action,
        "created_at": {"datetime": "2026-11-05 10:00:00", "formatted": "x"},
        "item": {"id": 7, "name": "Laptop &amp; Dock", "type": "asset", "serial": "SN1"},
        "target": {"id": 3, "name": "Jane Doe", "type": "user"},
        "created_by": {"id": 1, "name": "Admin"},
        "log_meta": {"name": {"old": "a", "new": "b"}} if action == "update" else None,
        "note": None,
    }


class FakeApi:
    """Mimics /api/v1/reports/activity sort=id paging semantics."""

    def __init__(self, ids):
        self.ids = list(ids)
        self.calls = 0
        self.on_call = None

    def activity(self, offset, limit, order):
        self.calls += 1
        if self.on_call:
            self.on_call(self)
        ordered = sorted(self.ids, reverse=(order == "desc"))
        return len(ordered), [row(i) for i in ordered[offset:offset + limit]]


class Collect:
    def __init__(self):
        self.msgs = []

    def send(self, msg):
        self.msgs.append(msg)

    def flush(self):
        pass

    @property
    def ids(self):
        return [m["_snipeit_log_id"] for m in self.msgs]


def make_cfg(tmp, **over):
    env = {"SNIPEIT_URL": "https://assets.example.com", "SNIPEIT_API_TOKEN": "t",
           "STATE_FILE": os.path.join(tmp, "state.json"), "HEALTH_FILE": os.path.join(tmp, "h"),
           "PAGE_SIZE": "3", "REQUEST_DELAY": "0"}
    env.update(over)
    with mock.patch.dict(os.environ, env, clear=False):
        return exporter.Config()


class ExporterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def build(self, api, **over):
        cfg = make_cfg(self.tmp, **over)
        out = Collect()
        return exporter.Exporter(cfg, api=api, output=out, state=exporter.State(cfg.state_file)), out

    def test_backfill_then_tail(self):
        api = FakeApi(range(1, 11))
        exp, out = self.build(api)
        exp.poll_once()
        self.assertEqual(out.ids, list(range(1, 11)))
        self.assertEqual(exp.state.phase, "tail")
        api.ids += [11, 12, 13, 14, 15]
        exp.poll_once()
        self.assertEqual(sorted(out.ids), list(range(1, 16)))
        exp.poll_once()  # nothing new
        self.assertEqual(len(out.ids), 15)

    def test_state_survives_restart(self):
        api = FakeApi(range(1, 6))
        exp, out = self.build(api)
        exp.poll_once()
        api.ids += [6, 7]
        exp2, out2 = self.build(api)
        exp2.poll_once()
        self.assertEqual(sorted(out2.ids), [6, 7])

    def test_start_from_now(self):
        api = FakeApi(range(1, 6))
        exp, out = self.build(api, START_FROM="now")
        exp.poll_once()
        self.assertEqual(out.ids, [])
        api.ids.append(6)
        exp.poll_once()
        self.assertEqual(out.ids, [6])

    def test_tail_tolerates_deletions(self):
        api = FakeApi(range(1, 6))
        exp, out = self.build(api)
        exp.poll_once()
        api.ids = [1, 2] + list(range(6, 14))  # 3,4,5 deleted, 8 new rows
        exp.poll_once()
        self.assertEqual(sorted(out.ids), list(range(1, 14)))

    def test_inserts_during_tail_paging_no_loss_no_dup(self):
        api = FakeApi(range(1, 4))
        exp, out = self.build(api)
        exp.poll_once()
        api.ids += list(range(4, 12))
        nxt = iter(range(12, 15))

        def insert(a):
            new = next(nxt, None)
            if new:
                a.ids.append(new)

        api.on_call = insert
        exp.poll_once()
        api.on_call = None
        exp.poll_once()
        self.assertEqual(sorted(out.ids), sorted(set(out.ids)))
        self.assertEqual(sorted(out.ids), list(range(1, 15)))

    def test_late_committed_id_is_picked_up(self):
        api = FakeApi([1, 2, 3, 5, 6])  # 4 not committed yet
        exp, out = self.build(api)
        exp.poll_once()
        api.ids += [4, 7]
        exp.poll_once()
        exp.poll_once()
        self.assertEqual(sorted(out.ids), [1, 2, 3, 4, 5, 6, 7])

    def test_lookback_survives_restart_without_dups(self):
        api = FakeApi(range(1, 8))
        exp, out = self.build(api)
        exp.poll_once()
        exp.poll_once()
        exp2, out2 = self.build(api)
        exp2.poll_once()
        self.assertEqual(out2.ids, [])

    def test_failed_send_does_not_advance_state(self):
        api = FakeApi(range(1, 4))
        exp, out = self.build(api)
        exp.poll_once()
        api.ids += [4, 5]
        exp.output.send = mock.Mock(side_effect=OSError("down"))
        with self.assertRaises(OSError):
            exp.poll_once()
        self.assertEqual(exp.state.last_id, 3)

    def test_gelf_mapping(self):
        cfg = make_cfg(self.tmp, SNIPEIT_TIMEZONE="Europe/Bratislava", GELF_EXTRA_FIELDS='{"env":"prod"}')
        r = row(42, "update")
        msg = exporter.to_gelf(r, cfg)
        self.assertEqual(msg["short_message"], "Admin update asset 'Laptop & Dock' -> user 'Jane Doe'")
        self.assertEqual(msg["_snipeit_log_id"], 42)
        self.assertEqual(msg["_item_name"], "Laptop & Dock")
        self.assertEqual(msg["_changed_fields"], "name")
        self.assertEqual(msg["_env"], "prod")
        self.assertEqual(msg["host"], "assets.example.com")
        self.assertNotIn("_note", msg)
        self.assertEqual(msg["timestamp"], 1793869200.0)  # 10:00 CET == 09:00 UTC
        for key in msg:
            self.assertRegex(key, r"^[\w\.\-]+$")
            self.assertNotEqual(key, "_id")

    def test_bogus_created_at_falls_back_to_updated_at(self):
        cfg = make_cfg(self.tmp)
        r = row(7919)
        r["created_at"] = {"datetime": "1970-01-01 01:00:56"}
        r["updated_at"] = {"datetime": "2024-12-30 11:32:51"}
        msg = exporter.to_gelf(r, cfg)
        self.assertEqual(msg["timestamp"], 1735558371.0)
        self.assertEqual(msg["_created_at_raw"], "1970-01-01 01:00:56")
        self.assertEqual(msg["_timestamp_fallback"], "updated_at")
        self.assertNotIn("_created_at_raw", exporter.to_gelf(row(1), cfg))

    def test_changed_field_flags(self):
        cfg = make_cfg(self.tmp)
        r = row(5, "update")
        r["log_meta"] = {"Status Label": {"old": "a", "new": "b"},
                         "_snipeit_ram_4": {"old": "8", "new": "16"}, "notes": {"old": "", "new": "x"}}
        msg = exporter.to_gelf(r, cfg)
        self.assertEqual(msg["_changed_fields"], "Status Label,_snipeit_ram_4,notes")
        self.assertEqual(msg["_changed_status_label"], 1)
        self.assertEqual(msg["_changed_snipeit_ram_4"], 1)
        self.assertEqual(msg["_changed_notes"], 1)
        self.assertNotIn("_snipeit_security", msg)
        self.assertNotIn("_changed_name", exporter.to_gelf(row(6), cfg))

    def test_security_class(self):
        cfg = make_cfg(self.tmp)

        def cls(action, item_type, meta=None):
            r = row(1, action)
            r["item"]["type"] = item_type
            r["log_meta"] = {k: {"old": "", "new": "x"} for k in (meta or [])}
            return exporter.to_gelf(r, cfg).get("_snipeit_security")

        self.assertEqual(cls("create new", "user"), "user_lifecycle")
        self.assertEqual(cls("restore", "user"), "user_lifecycle")
        self.assertEqual(cls("update", "user", ["email", "permissions"]), "user_privileges")
        self.assertEqual(cls("update", "user", ["Groups"]), "user_privileges")
        self.assertEqual(cls("update", "user", ["username"]), "user_identity")
        self.assertIsNone(cls("update", "user", ["locale"]))
        self.assertEqual(cls("delete", "asset"), "item_deleted")
        self.assertIsNone(cls("checkout", "asset"))


class TransportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_tcp(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cfg = make_cfg(self.tmp, GRAYLOG_HOST="127.0.0.1", GRAYLOG_PORT=str(srv.getsockname()[1]))
        out = exporter.GelfTcp(cfg)
        out.send({"short_message": "a"})
        out.send({"short_message": "b"})
        conn, _ = srv.accept()
        out.close()
        data = b""
        while chunk := conn.recv(4096):
            data += chunk
        self.assertEqual([json.loads(p) for p in data.split(b"\0") if p],
                         [{"short_message": "a"}, {"short_message": "b"}])

    def test_udp_chunked(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        cfg = make_cfg(self.tmp, GRAYLOG_HOST="127.0.0.1", GRAYLOG_PORT=str(srv.getsockname()[1]),
                       GRAYLOG_PROTOCOL="udp", GELF_UDP_CHUNK_SIZE="200")
        big = {"short_message": os.urandom(1500).hex()}
        exporter.GelfUdp(cfg).send(big)
        parts = {}
        while True:
            pkt = srv.recv(65535)
            self.assertEqual(pkt[:2], b"\x1e\x0f")
            parts[pkt[10]] = pkt[12:]
            if len(parts) == pkt[11]:
                break
        self.assertEqual(json.loads(zlib.decompress(b"".join(parts[i] for i in sorted(parts)))), big)

    def test_http(self):
        got = []

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                got.append(json.loads(zlib.decompress(body)))
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        cfg = make_cfg(self.tmp, GRAYLOG_HOST="127.0.0.1", GRAYLOG_PORT=str(srv.server_port),
                       GRAYLOG_PROTOCOL="http")
        out = exporter.GelfHttp(cfg)
        out.send({"short_message": "a"})
        out.send({"short_message": "b"})
        out.conn.close()
        srv.shutdown()
        self.assertEqual(got, [{"short_message": "a"}, {"short_message": "b"}])


if __name__ == "__main__":
    unittest.main()
