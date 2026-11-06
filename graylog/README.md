# Graylog setup (companion)

`setup_graylog.py` prepares Graylog for the exporter. It is Python stdlib only and talks to the
Graylog REST API. It needs an existing **GELF input** (TCP recommended, System → Inputs), and it
creates:

| object | what it does |
|---|---|
| index set `snipe-it` (prefix `snipeit`) | keeps the audit log apart from other data. Retention defaults to 1-3 years (`--lifetime-min/--lifetime-max`). The volume is tiny: roughly 10k events over 4 years for a 300-asset install |
| stream `snipe-it` | rule `application` == `snipe-it` (set by the exporter on every message), removes matches from the Default Stream |
| inverted rule on each `--exclude-from` stream | only needed if a catch-all stream already takes everything from your GELF input. Without the exclusion, the audit log would be stored twice |

It needs no pipeline. The exporter sends every field ready to search, including
`_changed_<name>=1` flags for each changed field and the `_snipeit_security` classification (see the
main README).

```bash
export GRAYLOG_URL=https://graylog.example.com:9000
export GRAYLOG_API_TOKEN_FILE=~/.graylog-token        # or GRAYLOG_API_TOKEN=...
python3 setup_graylog.py                              # dry run: prints what it would do
python3 setup_graylog.py --exclude-from GELF-TCP --apply
```

Objects are matched by title, so re-running it is safe and changes nothing. `--help` lists the
options for other titles, prefixes and retention. Tested against Graylog 7.2.

## Things to know

* **The backfill is stored under the original event times.** The first run sends the whole history
  with each action's real `created_at`, which can be years back. A relative search such as "last
  5 minutes" or "last 30 days" filters on that event time, so it won't show a backfill that just
  arrived. Use an absolute range, or "all messages", to see it.
* **Retention runs per index, not per message.** The whole backfill lands in the first index, and
  that index is deleted as one unit once it ages past `--lifetime-max`. Snipe-IT keeps the full
  history itself, so the exporter can backfill again at any time (delete its state file).

## Useful searches

```
streams:<snipe-it stream id>                           # or pick the stream in the UI
snipeit_security:user_privileges                       # permissions / group changes on users
snipeit_security:(user_lifecycle OR user_identity)     # accounts created/deleted, logins changed
snipeit_security:item_deleted
_exists_:changed_purchase_cost OR _exists_:changed_order_number
action_type:checkout AND target_name:"Jane Doe"
item_serial:SN123
action_source:api                                      # changes made through API tokens
```
