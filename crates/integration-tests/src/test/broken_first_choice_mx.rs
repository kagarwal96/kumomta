use crate::kumod::{DaemonWithMaildir, MailGenParams};
use anyhow::Context;
use kumo_log_types::smtp::SmtpConnectionPlanRecord;
use kumo_log_types::RecordType::{Delivery, TransientFailure};
use std::collections::BTreeMap;
use std::time::Duration;

/// We're sending to broken-first-mx which is defined in source.lua
/// to have a non-routable first MX in its connection plan, followed
/// by the regular sink.  This should cause a connection failure
/// for the first candidate, but we should then successfully
/// deliver to the second candidate.
async fn deliver_via_backup(daemon: &DaemonWithMaildir) -> anyhow::Result<()> {
    let mut client = daemon.smtp_client().await?;

    let response = MailGenParams {
        recip: Some("first@broken-first-mx.example.com"),
        ..Default::default()
    }
    .send(&mut client)
    .await?;
    eprintln!("{response:?}");
    anyhow::ensure!(response.code == 250);

    assert!(
        daemon
            .wait_for_source_summary(|s| s.contains_key(&Delivery), Duration::from_secs(50))
            .await,
        "expected a source Delivery"
    );
    assert!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await,
        "expected the backup to deliver to the maildir"
    );
    Ok(())
}

#[tokio::test]
async fn broken_first_choice_mx() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildir::start().await?;
    deliver_via_backup(&daemon).await?;
    let setup = daemon
        .source
        .api_client()
        .get_metrics(|m| {
            m.name()
                .starts_with("smtp_client_setup_")
                .then(|| m.name().clone())
        })
        .await?;
    assert!(setup.is_empty(), "telemetry disabled: {setup:?}");
    daemon.stop_both().await?;

    let delivery_summary = daemon.dump_logs().await?;
    k9::snapshot!(
        delivery_summary,
        "
DeliverySummary {
    source_counts: {
        Reception: 1,
        Delivery: 1,
    },
    sink_counts: {
        Reception: 1,
        Delivery: 1,
    },
}
"
    );

    k9::snapshot!(
        daemon.source.accounting_stats()?,
        "
AccountingStats {
    received: 1,
    delivered: 1,
}
"
    );

    let logs = daemon.source.collect_logs().await?;
    let delivered = logs.iter().find(|record| record.kind == Delivery).unwrap();

    k9::assert_equal!(delivered.peer_address.as_ref().unwrap().name, "workinghost");
    assert!(delivered.smtp.is_none());

    Ok(())
}

#[tokio::test]
async fn smtp_telemetry_on_mx_failover() -> anyhow::Result<()> {
    let mut daemon =
        DaemonWithMaildir::start_with_env(vec![("KUMOD_TEST_SMTP_TELEMETRY", "1")]).await?;
    deliver_via_backup(&daemon).await?;

    // The failed first host and the mixed plan are `other`; only the backup
    // and its successful transaction belong to `sink`.
    let samples: BTreeMap<_, _> = daemon
        .source
        .api_client()
        .get_metrics(|m| {
            let family = m.name().strip_prefix("smtp_client_")?;
            let (group, outcome) = match family {
                "setup_first_candidate_total" => ("other", "failed"),
                "plan_attempts" | "setup_duration_seconds" => ("other", "ready"),
                "setup_phase_duration_seconds"
                    if m.label_is("phase", "tcp_connect") && m.label_is("outcome", "error") =>
                {
                    ("other", "error")
                }
                "transaction_duration_seconds" => ("sink", "accepted"),
                _ => return None,
            };
            assert!(
                m.label_is("destination_relay_group", group) && m.label_is("outcome", outcome),
                "{m:?}"
            );
            if m.is_histogram() {
                assert_eq!(m.as_histogram().count, 1.0, "{m:?}");
            }
            Some((family.to_string(), m.value()))
        })
        .await?
        .into_iter()
        .collect();
    assert_eq!(samples["setup_first_candidate_total"], 1.0);
    assert_eq!(samples["plan_attempts"], 2.0);
    daemon.stop_both().await?;

    let plans = daemon
        .source
        .read_log_records::<SmtpConnectionPlanRecord>("plans")
        .await?;
    let [record] = plans.as_slice() else {
        anyhow::bail!("expected one plan, got {plans:?}")
    };
    eprintln!("{}", serde_json::to_string(record)?);
    let plan = &record.plan;
    assert_eq!(plan.result.as_str(), "recovered");
    let endpoints: Vec<_> = plan
        .attempts
        .iter()
        .map(|a| (a.mx.as_str(), a.outcome.as_str()))
        .collect();
    assert_eq!(
        endpoints,
        [("brokenhost", "failed"), ("workinghost", "smtp_ready")]
    );

    let logs = daemon.source.collect_logs().await?;
    assert!(!logs.iter().any(|r| r.kind == TransientFailure));
    let delivered = logs
        .iter()
        .find(|r| r.kind == Delivery)
        .context("missing Delivery")?;
    assert_eq!(delivered.session_id, Some(plan.session_id));
    let smtp = delivered
        .smtp
        .as_ref()
        .context("missing Delivery telemetry")?;
    assert_eq!(
        smtp.connection_id,
        Some(plan.connection_id.context("missing plan connection ID")?)
    );
    assert_eq!(smtp.transaction_number, Some(1));

    // These are the same observations in seconds and milliseconds, respectively.
    let failed_tcp = plan.attempts[0]
        .phases
        .iter()
        .find(|p| p.phase.as_str() == "tcp_connect")
        .context("missing failed TCP phase")?;
    for (family, millis) in [
        ("setup_phase_duration_seconds", failed_tcp.elapsed_ms),
        ("setup_duration_seconds", plan.connection_setup_ms),
        ("transaction_duration_seconds", smtp.transaction_elapsed_ms),
    ] {
        assert_eq!(
            Duration::from_secs_f64(samples[family]),
            Duration::from_secs_f64(millis.context(family)? / 1000.0),
            "{family}"
        );
    }
    Ok(())
}
