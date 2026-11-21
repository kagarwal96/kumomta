# smtp_client_classify_peer_reply

{{since('dev')}}

With [outbound SMTP client telemetry](../kumo/configure_smtp_client_telemetry.md) enabled, this optional event classifies a genuine negative SMTP reply before disposition policy rewrites it. The arguments are a bounded provider group, an SMTP stage without arguments, and a table with `code`, an optional `enhanced_code` (`class`, `subject`, `detail`), and optional `content`. There is no command or envelope. `content` is untrusted peer input. It is withheld for AUTH, unknown stages and incomplete or oversized text.

Return a table with optional `reason` (a configured metric label) and `content` (text approved for the local log). For example:

```lua
kumo.on('smtp_client_classify_peer_reply', function(provider, stage, response)
  if stage == 'rcpt_to' and response.content == 'Recipient rate limit reached' then
    return { reason = 'rate_limited', content = 'Recipient rate limit reached' }
  end
end)
```

Never pass arbitrary peer text to a log or return it unchanged: it can contain addresses, credentials or message content. Prefer known phrases or generate a safe explanation. Returned text is omitted if input text was withheld or the returned text contains control characters. Text is limited to 256 UTF-8 bytes; `content_truncated` indicates clipping. An absent or failed handler gives `reason="other"` and no text. A returned reason outside the configured list also maps to `other`.

Keep the handler fast and local. An async classification that takes too long falls back to the same default. If the client cannot retain a reply for classification, it still counts the refusal with `reason="other"`. This event does not set the SMTP disposition.
