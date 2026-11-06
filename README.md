# Snipe-IT audit log exporter → Graylog

Small Docker image (~46 MB, Python stdlib only). It ships Snipe-IT's activity / audit log
(`action_logs` table) to Graylog as GELF over TCP, UDP or HTTP.

## Why the API and not the database

| | REST API (`/api/v1/reports/activity`) | Direct DB (`action_logs`) |
|---|---|---|
| Data quality | Resolved names for item, target, admin and location; `log_meta` diffs with **encrypted custom fields decrypted** | Raw FKs and polymorphic `item_type` class names; you have to join 6+ tables yourself; `log_meta` is serialized PHP or JSON, with encrypted values left encrypted |
| Schema stability | Stable, versioned contract | Columns change between releases (for example `user_id` → `created_by`, `order_number` → `order_item_id` in v8) |
| Access | HTTPS plus an API token scoped to a user with `activity.view` | DB credentials and network access to MySQL, usually not exposed |
| Works with hosted Snipe-IT | Yes | No |
| Throughput | 500 rows/request (`MAX_RESULTS`), 120 req/min (`API_THROTTLE_PER_MINUTE`), so ~60k rows/min | Unlimited |
| Incremental cursor | No `id > N` filter, but `sort=id` is supported (handled below) | `WHERE id > :last` |

The API is the better choice. The DB is only faster for a one-off backfill of millions of rows, and
even 1M rows takes about 17 min over the API.

## Existing tools I checked

- **Fluent Bit**: has no SQL input and no paginating HTTP input. The only option is `exec`
  plus a curl script, which has no state or cursor handling. Not suitable.
- **Graylog "JSON path value from HTTP API" input**: extracts one value per poll, not a list of
  records. Not suitable.
- **Vector `http_client` source**: polls a URL but has no pagination or cursor state. Not suitable.
- **Fluentd + `fluent-plugin-sql` (input) + `fluent-plugin-gelf`**: works with the DB approach and
  tracks `id` as a cursor. You get the raw-DB downsides above, plus a Ruby image.
- **Logstash `jdbc` input + `gelf` output**: the most mature DB-based option (see the end of this
  README). It works, but it means a ~800 MB JVM container for one table, plus the raw-DB downsides.
- **Snipe-IT webhooks (Slack/Teams/generic)**: cover checkout/checkin only, not the full audit trail.

None of these gives you resolved, decrypted events with a reliable cursor, so this project is a
purpose-built poller.

## How it works

1. **Backfill** (first start, `START_FROM=beginning`): walks the history oldest-first
   (`sort=id&order=asc`) and checkpoints after every page.
2. **Tail**: every `POLL_INTERVAL` it walks newest-first until it gets below the last exported id.
   Because it never relies on a stored offset, deleted rows don't break it.
3. **Lookback**: MySQL can make a lower auto-increment id visible after a higher one, because
   transactions commit out of order. Each poll re-checks the last `LOOKBACK_IDS` ids, and the
   state file stores which of those were already sent, so late rows are picked up without
   duplicates.
4. Delivery is **at-least-once**. The state only advances after a successful send. Every message
   carries `_snipeit_log_id`, so any duplicates after a crash can be spotted.

State lives in `/data/state.json`. Mount a volume there.

## Quick start

1. In Graylog, create a **GELF TCP** input (System → Inputs), port 12201.
2. Give the audit log its own stream and index set with [`graylog/setup_graylog.py`](graylog/)
   (dry run by default). You can skip this, and the messages land in the Default Stream.
3. In Snipe-IT, create an API key for a user that can view reports/activity. A dedicated
   read-only user is best.
4. Run the prebuilt image (`linux/amd64` and `linux/arm64`, built by GitHub Actions):

```bash
cp .env.example .env
# edit SNIPEIT_URL, SNIPEIT_API_TOKEN, SNIPEIT_TIMEZONE, GRAYLOG_HOST in .env
docker compose pull && docker compose up -d
docker compose logs -f
```

To build the image yourself instead, run `docker compose up -d --build`.

Or with plain docker:

```bash
docker run -d --name snipeit-audit-exporter --env-file .env -v snipeit-exporter:/data \
  ghcr.io/tomaskovacik/snipe-it-audit-log-exporter:latest
```

Image tags: `latest` (main branch), `1.0.0` / `1.0` / `1` (releases), `sha-<commit>`.

To test without Graylog, set `OUTPUT=stdout` and run with `--once`. That prints GELF JSON lines:
`docker run --rm --env-file .env -e OUTPUT=stdout -e STATE_FILE=/tmp/s.json ghcr.io/tomaskovacik/snipe-it-audit-log-exporter --once`.

## Configuration

All settings are documented in [`.env.example`](.env.example). Every variable also accepts a `*_FILE` variant, for Docker/K8s secrets.

| Variable | Default | Description |
|---|---|---|
| `SNIPEIT_URL` | *required* | Base URL, e.g. `https://snipeit.example.com` |
| `SNIPEIT_API_TOKEN` | *required* | Personal API token |
| `SNIPEIT_VERIFY_TLS` | `true` | Verify the Snipe-IT certificate |
| `SNIPEIT_TIMEZONE` | `UTC` | Snipe-IT `APP_TIMEZONE`. The API returns local times without an offset |
| `POLL_INTERVAL` | `60` | Seconds between polls |
| `PAGE_SIZE` | `500` | Rows per request. Capped by Snipe-IT `MAX_RESULTS` |
| `REQUEST_DELAY` | `0.6` | Minimum seconds between API calls, to stay under the 120/min throttle. HTTP 429 is retried using `Retry-After` |
| `START_FROM` | `beginning` | First run only: `beginning` = full backfill, `now` = new events only |
| `LOOKBACK_IDS` | `100` | Window for late-committed ids |
| `STATE_FILE` | `/data/state.json` | Checkpoint file |
| `OUTPUT` | `gelf` | `gelf` or `stdout` |
| `GRAYLOG_HOST` / `GRAYLOG_PORT` | `graylog` / `12201` | GELF input address |
| `GRAYLOG_PROTOCOL` | `tcp` | `tcp` (recommended), `udp` (zlib, chunked), `http` (POST to `GRAYLOG_HTTP_PATH`, default `/gelf`) |
| `GRAYLOG_TLS` / `GRAYLOG_VERIFY_TLS` | `false` / `true` | TLS for TCP/HTTP inputs |
| `GELF_SOURCE` | Snipe-IT hostname | GELF `host` (Graylog *source*) |
| `GELF_EXTRA_FIELDS` | `{}` | JSON object of static fields, e.g. `{"environment":"prod"}` |
| `GELF_INCLUDE_RAW` | `true` | Put the full API record into `full_message` |
| `LOG_LEVEL` | `INFO` | Exporter log level (stderr) |

## GELF fields

`short_message` reads like `Admin checkout asset 'MacBook Pro' -> user 'Jane Doe'`. `timestamp` is
the action's `created_at`.

Fields: `_snipeit_log_id`, `_action_type` (checkout, checkin from, update, create, delete, audit,
uploaded, accepted, ...), `_action_source`, `_action_date`, `_item_type`, `_item_id`,
`_item_name`, `_item_serial`, `_target_type`, `_target_id`, `_target_name`, `_admin_id`,
`_admin_name`, `_location_id`, `_location_name`, `_quantity`, `_order_number`, `_note`,
`_remote_ip`, `_user_agent`, `_changed_fields` (comma-separated), `_log_meta` (JSON old/new diff),
plus `_application=snipe-it` and `_event_type=audit`. Empty fields are left out.

Every changed field also gets its own flag, `_changed_<name>=1`. The name is lowercased, and
anything that isn't a letter or digit becomes `_`: `Status Label` → `_changed_status_label`,
`_snipeit_ram_4` → `_changed_snipeit_ram_4`. GELF can't carry a list (Graylog stores one as a
JSON string), and finding one name inside the comma-separated `_changed_fields` needs a leading
wildcard, which Graylog disables by default. The flags make that a plain term search.

`_snipeit_security` classifies the security-relevant events:

| value | when |
|---|---|
| `user_lifecycle` | a user is created, deleted or restored |
| `user_privileges` | a user update changes `permissions` or `Groups` |
| `user_identity` | a user update changes `username`, `email`, `password` or `activated` (and not privileges) |
| `item_deleted` | anything other than a user is deleted |

If Snipe-IT stored a bogus `created_at` (before 2000, e.g. `1970-01-01` from some bulk checkins), the message uses `updated_at` as its timestamp and adds `_created_at_raw` and `_timestamp_fallback=updated_at`.

Example Graylog searches: `_application:snipe-it AND action_type:delete`,
`item_serial:SN123`, `admin_name:"John Smith" AND _exists_:changed_purchase_cost`,
`snipeit_security:user_privileges`.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Alternative: Logstash JDBC (DB approach)

For reference only, if you really need to read the DB directly. It needs the MySQL JDBC driver jar
and a read-only DB user.

```conf
input {
  jdbc {
    jdbc_driver_library => "/usr/share/logstash/drivers/mysql-connector-j.jar"
    jdbc_driver_class => "com.mysql.cj.jdbc.Driver"
    jdbc_connection_string => "jdbc:mysql://snipeit-db:3306/snipeit"
    jdbc_user => "readonly"
    jdbc_password => "${SNIPEIT_DB_PASSWORD}"
    schedule => "* * * * *"
    statement => "SELECT l.*, CONCAT(u.first_name,' ',u.last_name) AS admin_name
                  FROM action_logs l LEFT JOIN users u ON u.id = l.created_by
                  WHERE l.id > :sql_last_value ORDER BY l.id LIMIT 5000"
    use_column_value => true
    tracking_column => "id"
    tracking_column_type => "numeric"
    last_run_metadata_path => "/usr/share/logstash/data/.snipeit_last_id"
  }
}
output {
  gelf { host => "graylog" port => 12201 protocol => "TCP" short_message => "action_type" }
}
```

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
