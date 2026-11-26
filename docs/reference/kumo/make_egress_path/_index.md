# kumo.make_egress_path

```lua
kumo.make_egress_path { PARAMS }
```

Constructs a configuration object that specifies how traffic travelling the
path from a *source* to a *site* will behave.

This function should be called from the
[get_egress_path_config](../../events/get_egress_path_config.md) event handler to provide the
configuration for the requested site.

{{since('dev', indent=True)}}
    The outbound SMTP client accepts up to 8 KiB per reply, including status
    codes, separators, and CRLF. The initial greeting uses
    [`banner_timeout`](banner_timeout.md). For command replies, the timeout
    depends on the command: for example, [`ehlo_timeout`](ehlo_timeout.md) for
    `EHLO`, [`mail_from_timeout`](mail_from_timeout.md) for `MAIL FROM`,
    [`rcpt_to_timeout`](rcpt_to_timeout.md) for each `RCPT TO`,
    [`data_timeout`](data_timeout.md) for `DATA`, and
    [`data_dot_timeout`](data_dot_timeout.md) for the final reply after the
    terminating dot. Each timeout covers the entire reply and does not restart
    as bytes or lines arrive. Each continuation line must also arrive within
    60 seconds. The client closes the connection if a reply exceeds the size
    limit or a deadline expires.

The following keys are possible:

## Egress Path Parameters { data-search-exclude }
