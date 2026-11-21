# kumo.configure_smtp_client_telemetry

{{since('dev')}}

Enables outbound SMTP client telemetry. Without this call the telemetry is disabled. Call it from [init](../events/init.md). The allowlists are fixed for the lifetime of the process; restart to change them. An empty configuration enables telemetry with empty allowlists.

```lua
kumo.on('init', function()
  kumo.configure_smtp_client_telemetry {
    providers = {
      example_gateway = { 'mx.example.net', '=smtp.example.org' },
    },
    enhanced_codes = { '4.2.1', '5.1.1' },
    reasons = { 'rate_limited' },
  }
end)
```

* `providers` maps a group to SMTP next-hop hostname rules. A bare domain matches that domain and its descendants; `*.example.net` matches descendants only; `=smtp.example.net` matches only that host. Matching is case-insensitive, ignores a final root dot and port, and prefers the longest matching domain. Use ASCII DNS names or their Punycode forms. An unmatched host or mixed plan maps to `other`; missing MX information maps to `unknown`. The MX lookup phase always uses `unknown`.
* `enhanced_codes` lists canonical enhanced status codes of class 4 or 5. A valid peer code outside this list maps to `dsn="other"`; an absent or unusable code (including a class inconsistent with the SMTP reply) maps to `dsn="unknown"`. The structured peer response keeps the supplied code independently of the metric label.
* `reasons` lists labels that [smtp_client_classify_peer_reply](../events/smtp_client_classify_peer_reply.md) may assign to a negative peer reply. The default is `other`.

At most 32 provider groups, 128 hostname rules in total, 32 enhanced codes, and 16 reason labels are accepted. Provider and reason labels start with a lowercase ASCII letter and contain at most 48 lowercase letters, digits or underscores. `other` and `unknown` are reserved provider groups.

The `smtp_client_` counters and histograms appear at the [metrics endpoint](../http/kumod/metrics_get.md) as observations occur. Duration histograms use seconds. Attempts and transactions per connection are histogram values, not labels. Each classic histogram exports one series per finite bucket, plus `+Inf`, sum and count.

Every 400–599 reply read from the peer increments [smtp_client_peer_refusals_total](../metrics/kumod/smtp_client_peer_refusals_total.md) once, including secondary replies in a transaction. Each observed combination of `destination_relay_group`, numeric `smtp_code`, normalized `dsn`, and normalized `reason` gets its own counter. Reply text and addresses are never labels. Locally assigned status codes, including those for timeouts, do not count as peer replies.
