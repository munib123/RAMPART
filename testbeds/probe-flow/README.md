# probe-flow - one vulnerable function and one fixed twin per call-anchored rule

The DEV target for the eight rules in `rules/50-60` (2026-10). shopfast shows each of them once;
this shows each of them **with its fix next to it**, so precision is pinned by the bench instead
of by reading the rule. Flask-flavoured; not runnable, a static target only. Key:
`bench/keys/probe-flow.key.jsonl` (10 vuln rows, 12 safe rows).

| rule | vulnerable | must stay quiet |
|---|---|---|
| ignored-auth-result | `app.login` (project check, None-or-value returns), `auth.change_email` (`check_password_hash` as a statement) | `login_safe`, `change_email_safe` |
| hardcoded-credential-compare | `auth.is_support_login` (`password == settings.SUPPORT_PASSWORD`) | `is_support_login_safe` (value from the environment) |
| ssrf-request-url | `client.notify` (input arrives through `app.webhook`), `app.preview` (same function) | `notify_safe` (host allow-list), `charge` (constant URL), `webhook_safe` (the caller is not the sink) |
| path-traversal | `files.read_export` (input arrives through `app.export`) | `read_export_safe` (`secure_filename`) |
| xxe-parser | `feeds.parse_partner_feed` | `parse_partner_feed_safe` |
| cleartext-transport | `settings.GATEWAY_URL` (used by `client.charge`) | `settings_safe.GATEWAY_URL` (https), `settings_safe.METRICS_URL` (loopback) |
| cors-wildcard | `settings.CORS_ORIGIN` (applied by `app.add_cors`) | `settings_safe.CORS_ORIGIN`, `app.add_cors_public` (conditional: a policy, by design) |
| debug-exposed | `settings.DEBUG` (`app.run(debug=settings.DEBUG)`) | `settings_safe.DEBUG` (`run_safe`) |

The config-flow rules report the line that DEFINES the unsafe value (settings.py), because that is
the line a fix changes; the message names the sink that consumes it.

    python -m bench.run --backend joern --benchmark probe-flow --pack _base
