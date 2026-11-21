use crate::kumod::{DaemonWithMaildir, DaemonWithMaildirOptions, MailGenParams};
use anyhow::Context;
use kumo_log_types::smtp::SmtpDispositionFields;
use kumo_log_types::RecordType::TransientFailure;
use std::time::Duration;

type Refusals = Vec<([String; 4], f64)>;

async fn peer_refusals(daemon: &DaemonWithMaildir) -> anyhow::Result<Refusals> {
    let mut refusals = daemon
        .source
        .api_client()
        .get_metrics(|m| {
            (m.name().as_str() == "smtp_client_peer_refusals_total").then(|| {
                let keys = ["destination_relay_group", "smtp_code", "dsn", "reason"];
                assert_eq!(
                    m.labels().len(),
                    keys.len(),
                    "unexpected peer reply labels: {m:?}"
                );
                (keys.map(|key| m.labels()[key].to_string()), m.value())
            })
        })
        .await?;
    refusals.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(refusals)
}

#[tokio::test]
async fn temp_fail() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_TEST_SMTP_TELEMETRY", "classify")
        .env("KUMOD_TEST_SINK_CLIENT_TIMEOUT", "1m")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    for recip in ["tempfail@example.com", "full-enh@example.com"] {
        let response = MailGenParams {
            recip: Some(recip),
            ..Default::default()
        }
        .send(&mut client)
        .await?;
        assert_eq!(response.code, 250);
    }
    assert!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure) == Some(&2),
                Duration::from_secs(50)
            )
            .await
    );

    // Each pipelined transaction has a primary RCPT refusal and a secondary
    // DATA refusal. The latter is counted even when its classifier throws.
    assert_eq!(
        peer_refusals(&daemon).await?,
        [
            (
                ["sink", "400", "unknown", "temporary"].map(String::from),
                1.0
            ),
            (["sink", "452", "unknown", "other"].map(String::from), 1.0),
            (["sink", "503", "5.5.0", "other"].map(String::from), 2.0),
        ]
    );
    let api = daemon.source.api_client();
    // This route resolves localhost, so it exports a completed address-list build.
    let builds = api
        .get_metrics(|m| {
            (m.name().as_str() == "smtp_client_setup_address_list_build_duration_seconds").then(
                || {
                    assert!(m.as_histogram().count >= 1.0, "{m:?}");
                    m.labels()["outcome"].to_string()
                },
            )
        })
        .await?;
    assert_eq!(builds, ["complete"]);
    let mut uses = api
        .get_metrics(|m| {
            (m.name().as_str() == "smtp_client_transactions_total").then(|| {
                assert_eq!(m.value(), 1.0, "{m:?}");
                m.labels()["connection_use"].to_string()
            })
        })
        .await?;
    uses.sort();
    assert_eq!(uses, ["first", "reused"]);
    daemon.stop_both().await?;

    let failures = daemon.source.collect_logs().await?;
    for failure in failures.iter().filter(|r| r.kind == TransientFailure) {
        let smtp = failure.smtp.as_ref().context("missing SMTP telemetry")?;
        let primary = smtp.peer_response.as_ref().context("missing RCPT reply")?;
        assert_eq!(primary.code, failure.response.code);
        assert_eq!(primary.enhanced_code, failure.response.enhanced_code);
        assert_eq!(
            primary.content.as_deref(),
            (primary.code == 400).then_some("Retry later")
        );
        let [secondary] = smtp.peer_replies.as_slice() else {
            anyhow::bail!("expected a secondary DATA refusal: {smtp:?}")
        };
        assert_eq!(secondary.response.code, 503);
        assert!(secondary.response.content.is_none());
    }
    let delivery_summary = daemon.dump_logs().await?;
    k9::snapshot!(
        delivery_summary,
        "
DeliverySummary {
    source_counts: {
        Reception: 2,
        TransientFailure: 2,
    },
    sink_counts: {
        Rejection: 4,
    },
}
"
    );

    k9::snapshot!(
        daemon.source.accounting_stats()?,
        "
AccountingStats {
    received: 2,
    delivered: 0,
}
"
    );
    Ok(())
}

async fn data_dot_failure(
    options: DaemonWithMaildirOptions,
    outcome: &str,
) -> anyhow::Result<(SmtpDispositionFields, Refusals)> {
    let mut daemon = options
        .env("KUMOD_TEST_SMTP_TELEMETRY", "1")
        .start()
        .await?;
    let response = MailGenParams {
        sender: Some("disconnect-in-data-no-421@example.com"),
        ..Default::default()
    }
    .send(&mut daemon.smtp_client().await?)
    .await?;
    assert_eq!(response.code, 250);
    assert!(
        daemon
            .wait_for_source_summary(
                |s| s.contains_key(&TransientFailure),
                Duration::from_secs(10)
            )
            .await,
        "expected a source TransientFailure"
    );
    let refusals = peer_refusals(&daemon).await?;
    let outcomes = daemon
        .source
        .api_client()
        .get_metrics(|m| {
            (m.name().as_str() == "smtp_client_transaction_duration_seconds")
                .then(|| (m.labels()["outcome"].to_string(), m.as_histogram().count))
        })
        .await?;
    assert_eq!(outcomes, [(outcome.to_string(), 1.0)]);
    daemon.stop_both().await?;

    let record = daemon
        .source
        .collect_logs()
        .await?
        .into_iter()
        .find(|r| r.kind == TransientFailure)
        .context("missing TransientFailure")?;
    assert_eq!(record.response.code / 100, 4);
    let smtp = record.smtp.context("missing failure telemetry")?;
    assert_eq!(
        smtp.smtp_stage.as_ref().context("missing stage")?.as_str(),
        "data_dot"
    );
    Ok((*smtp, refusals))
}

#[tokio::test]
async fn smtp_telemetry_data_dot_peer_refusal() -> anyhow::Result<()> {
    let (smtp, refusals) = data_dot_failure(DaemonWithMaildirOptions::new(), "deferred").await?;
    assert_eq!(
        smtp.failure_kind.context("missing failure kind")?.as_str(),
        "smtp_reply"
    );
    let peer = smtp.peer_response.context("missing peer reply")?;
    assert_eq!(peer.code, 451);
    assert_eq!(peer.reason.context("missing reason")?.as_str(), "other");
    assert!(peer.content.is_none());
    assert_eq!(
        refusals,
        [(["sink", "451", "unknown", "other"].map(String::from), 1.0)]
    );
    Ok(())
}

#[tokio::test]
async fn smtp_telemetry_data_dot_timeout() -> anyhow::Result<()> {
    // The same peer withholds its 451 until after the client's DATA-dot deadline.
    let options = DaemonWithMaildirOptions::new()
        .env("KUMOD_TEST_DATA_DOT_TIMEOUT", "100ms")
        .env("KUMOD_TEST_SINK_DATA_DOT_DELAY", "2");
    let (smtp, refusals) = data_dot_failure(options, "transport_error").await?;
    assert_eq!(
        smtp.failure_kind.context("missing failure kind")?.as_str(),
        "response_timeout"
    );
    assert_eq!(smtp.transaction_number, Some(1));
    assert!(smtp.peer_response.is_none() && smtp.peer_replies.is_empty());
    assert!(
        refusals.is_empty(),
        "unexpected peer refusals: {refusals:?}"
    );
    Ok(())
}

#[tokio::test]
async fn smtp_telemetry_unused_ready_connection() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .env("KUMOD_HIDE_8BITMIME", "1")
        .env("KUMOD_TEST_SMTP_TELEMETRY", "unused")
        .start()
        .await?;
    // One message per socket: delivery, RCPT refusal, and a local 8BITMIME
    // failure before MAIL FROM. Only the last SMTP-ready socket is unused.
    let mut client = daemon.smtp_client().await?;
    for (recip, subject) in [
        ("ok@example.com", "plain"),
        ("tempfail@example.com", "plain"),
        ("unused@example.com", "👾"),
    ] {
        let content = format!("Subject: {subject}\r\n\r\nbody\r\n");
        let mail = MailGenParams {
            recip: Some(recip),
            full_content: Some(&content),
            ignore_8bit_checks: true,
            ..Default::default()
        };
        assert_eq!(mail.send(&mut client).await?.code, 250);
    }
    daemon
        .source
        .wait_for_metric(
            Duration::from_secs(10),
            |m| {
                if m.name().as_str() != "smtp_client_transactions_per_connection"
                    || !m.label_is("destination_relay_group", "sink")
                {
                    return false;
                }
                let h = m.as_histogram();
                let (sum, zeros) = match m.labels()["measure"].as_str() {
                    "attempted" => (2.0, 1.0),
                    "accepted" => (1.0, 2.0),
                    _ => return false,
                };
                (h.count, h.sum, h.bucket[0]) == (3.0, sum, (0.5, zeros))
            },
            |values| values.len() == 2,
        )
        .await
        .context("waiting for unused socket to close")?;
    daemon.stop_both().await
}
