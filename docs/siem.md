# SIEM forwarding

MCP-Gateway streams every audit event to your SIEM within seconds: logins, policy decisions, tool
invocations, approvals, configuration changes and emergency actions. Configure it in **Settings → SIEM
forwarding** as a platform administrator. It works fully inside an air-gapped network and needs no agent or
sidecar.

## Delivery guarantees

- **At least once, in timestamp order.** The forwarder runs in the worker and reads the audit collection.
  The audit collection *is* the outbox. A durable cursor records the newest event shipped.
- **Nothing is lost while the collector is down.** Nothing advances until the collector accepts the batch.
  Retries back off from 2 s to 5 minutes. When the collector recovers, the backlog is sent in order. Events
  are kept for as long as audit retention keeps them (365 days by default, `AUDIT_RETENTION_DAYS`).
- **Late writers are covered.** Each pass re-reads a 2-minute window behind the cursor and skips events
  already sent, and events younger than 5 s wait one more pass. An event committed slightly late by another
  API replica is delivered, not skipped.
- **Duplicates are rare but possible.** After a crash between "sent" and "recorded", or after a Redis loss,
  some events of the last 2 minutes may be sent twice. De-duplicate on `event_id` in the SIEM if you need to.
- **One sender.** With several worker replicas, one holds a 60 s lease, renewed before every batch, and forwards.
  A worker that loses the lease stops before moving the cursor. Another worker takes over at once when the holder
  stops cleanly, or within 60 s if it dies.
- **Enabling starts from now.** Turning forwarding on does not replay the existing audit history. Use the
  audit export (CSV/JSON) for a one-off backfill.
- **No impact on tool calls.** Forwarding never runs in the request path, so a slow or failed collector can't
  slow or block agents.

The transitions are audited and forwarded too: `siem.forwarding.failed` (once, when it starts failing) and
`siem.forwarding.recovered`, plus `siem.config.updated` for every configuration change.

## Transports

| Transport | Standard | Default port | Notes |
|---|---|---|---|
| Syslog over TLS | RFC 5424 messages, RFC 5425 framing | 6514 | **Recommended.** TLS 1.2+, certificate chain and host name verified. Paste an internal CA in *CA certificate (PEM)*. |
| Syslog over TCP | RFC 5424, RFC 6587 octet counting | 514 | Not encrypted. Use it only on a trusted segment. |
| Syslog over UDP | RFC 5424, RFC 5426 | 514 | Not encrypted, and **no delivery confirmation**: losses can't be detected. Only for legacy collectors. |
| HTTP(S) collector | POST, no redirects followed | n/a | Body: one event per line (NDJSON), a JSON array, or Splunk HEC. Optional auth header (write-only, stored AES-256-GCM encrypted). Any non-2xx response counts as a failure and is retried. |

**Destination rules:**
- **Blocked addresses:** link-local and cloud-metadata addresses (169.254.0.0/16, including the AWS ECS
  credentials endpoint), CGNAT, multicast and unspecified addresses are refused. This is checked when you save,
  and again at every connection after DNS resolution; the gateway connects to the address it checked.
  Private networks are allowed, since collectors usually live there.
- **Credential bound to the destination:** the stored auth value is only sent where it was saved for. Changing
  the transport, host, port, URL, auth header name or TLS settings requires entering it again (or clearing it).
- **Host name verification:** turning it off requires a pinned CA certificate. Otherwise any publicly trusted
  certificate for any name would be accepted.
- **Production:** an `http://` collector URL is refused while an auth value is stored.
- **Auth value characters:** the auth value must be printable ASCII.
- **Test errors:** *Send test event* reports a generic error (could not connect, timed out, TLS handshake
  failed). The underlying error is written to the worker log only.

Syslog header: `<PRI>1 <timestamp> <gateway host> mcp-gateway - <event_type> - <message>`. PRI uses the
configured facility (default 13, *log audit*) and a severity mapped from the event: info→6, warning→4,
high→3, critical→2.

## Formats

### JSON (default)

```json
{"@timestamp":"2026-11-16T06:00:00.000Z","source":"mcp-gateway","gateway_version":"0.1.0",
 "event_id":"evt_…","event_type":"auth.login.failed","severity":"high","tenant_id":"_system",
 "principal":{"type":"user","id":null,"name":"alice"},"delegated_by_user_id":null,"resource":{},
 "decision":null,"reason_code":null,"status":"failure","policy_ids":[],"request_id":"req_…",
 "invocation_id":null,"approval_id":null,"duration_ms":null,"input_hash":null,"output_hash":null,
 "metadata":{"source_ip":"10.1.2.3"}}
```

The fields are those of the audit log ([security model](security-model.md#audit)). Payloads and secrets are
never in the audit log, so they are never forwarded. Tool arguments and results appear only as SHA-256
hashes.

### CEF

`CEF:0|MCP-Gateway|MCP-Gateway|<version>|<event_type>|<event_type>|<severity>|<extensions>`, with CEF
severity info=3, warning=5, high=8, critical=10. Header fields escape `|` and `\`. Extension values escape
`=`, `\` and newlines.

| CEF key | Source |
|---|---|
| `rt` | event timestamp (epoch ms) |
| `externalId` | `event_id` |
| `cs1` (`tenantId`) | `tenant_id` |
| `suser`, `suid`, `cs2` (`principalType`) | principal name, id, type |
| `src` | `metadata.source_ip` |
| `outcome`, `act`, `reason` | `status`, `decision`, `reason_code` |
| `cs3` / `cs4` / `cs5` | request, invocation, approval IDs |
| `cs6` (`resource`) | resource, as compact JSON |
| `msg` | metadata, as compact JSON (truncated to 2,000 characters) |

## Filtering

- **Minimum severity**: all, warning and above, high and critical, or critical only.
- **Event types**: prefixes such as `auth.`, `policy.`, `emergency.`, `tool.invocation`. Empty means all.

Filtered-out events still advance the cursor. They are not sent later if you widen the filter.

## Collector examples

**rsyslog (TLS)**:

```
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.Authmode="anon")
global(DefaultNetstreamDriverCAFile="/etc/pki/ca.pem" DefaultNetstreamDriverCertFile="/etc/pki/siem.pem"
       DefaultNetstreamDriverKeyFile="/etc/pki/siem.key")
input(type="imtcp" port="6514")
if $app-name == "mcp-gateway" then /var/log/mcp-gateway/audit.log
```

**syslog-ng (TLS)**: `source s_mgw { syslog(transport("tls") port(6514) tls(key-file(...) cert-file(...) peer-verify(optional-untrusted))); };`

**Splunk**: create an HTTP Event Collector token. Transport *HTTP(S)*, URL
`https://<splunk>:8088/services/collector/event`, Body *Splunk HEC*, Auth header `Authorization`, value
`Splunk <token>`. Events arrive with `sourcetype=mcp-gateway:audit`.

**Elastic / Logstash**: a Logstash `http` input (`codec => json_lines`) with Body *One event per line*, or a
`syslog`/`tcp` input with the JSON format.

**QRadar / ArcSight**: syslog over TLS (or TCP) with the CEF format.

## Monitoring

The status panel and `/api/v1/siem/status` show events forwarded, events waiting, the age of the newest
event sent, and the last error. Prometheus (`/api/v1/metrics`) exposes `mgw_siem_up`,
`mgw_siem_forwarded_events`, `mgw_siem_lag_seconds` and `mgw_siem_pending_events`. Alert on
`mgw_siem_up == 0` or on a growing `mgw_siem_lag_seconds`.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/siem/config` | Returns `has_http_auth_value`, never the value |
| PUT | `/siem/config` | Full configuration. `http_auth_value`: omit to keep (only while the destination and TLS settings stay the same), `""` to clear. Audited. |
| GET | `/siem/status` | Forwarding status |
| POST | `/siem/test` | Sends one `siem.test` event using the saved settings |

All require the platform administrator role.
