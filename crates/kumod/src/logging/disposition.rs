use crate::logging::Logger;
use crate::smtp_server::RelayDisposition;
use bounce_classify::BounceClass;
use chrono::Utc;
use config::{load_config, CallbackSignature};
use kumo_log_types::rfc3464::ReportAction;
use kumo_log_types::smtp::SmtpDispositionFields;
use kumo_log_types::MaybeProxiedSourceAddress;
pub use kumo_log_types::*;
use message::Message;
use rfc5321::{EnhancedStatusCode, Response, TlsInformation};
use std::net::Ipv4Addr;
use uuid::Uuid;

pub struct LogDisposition<'a> {
    pub kind: RecordType,
    pub msg: Message,
    pub site: &'a str,
    pub peer_address: Option<&'a ResolvedAddress>,
    pub response: Response,
    pub egress_pool: Option<&'a str>,
    pub egress_source: Option<&'a str>,
    pub relay_disposition: Option<RelayDisposition>,
    pub delivery_protocol: Option<&'a str>,
    pub tls_info: Option<&'a TlsInformation>,
    pub source_address: Option<MaybeProxiedSourceAddress>,
    pub provider: Option<&'a str>,
    pub session_id: Option<Uuid>,
    /// if Some, specifies the recipient list to which this log
    /// applies, otherwise, the full msg.recipient_list_string()
    /// will be used
    pub recipient_list: Option<Vec<String>>,
}

pub async fn log_disposition(args: LogDisposition<'_>) {
    log_disposition_impl(args, None).await;
}

struct LocalSmtpDisposition<'a> {
    fields: &'a SmtpDispositionFields,
    peer_address: Option<&'a ResolvedAddress>,
}

/// Add SMTP diagnostics to local file records only. The saved peer address
/// identifies a transaction even when the native disposition has no peer.
pub async fn log_smtp_disposition(
    args: LogDisposition<'_>,
    mut fields: SmtpDispositionFields,
    local_peer_address: Option<&ResolvedAddress>,
) {
    let smtp = if matches!(
        args.kind,
        RecordType::Delivery | RecordType::Bounce | RecordType::TransientFailure
    ) {
        fields.limit();
        Some(LocalSmtpDisposition {
            fields: &fields,
            peer_address: local_peer_address,
        })
    } else {
        None
    };
    log_disposition_impl(args, smtp).await;
}

fn disposition_peer_and_smtp(
    hook_name: Option<&str>,
    native_peer: Option<&ResolvedAddress>,
    local: Option<&LocalSmtpDisposition<'_>>,
) -> (Option<ResolvedAddress>, Option<Box<SmtpDispositionFields>>) {
    match local {
        Some(local) if hook_name.is_none() => (
            local.peer_address.or(native_peer).cloned(),
            Some(Box::new(local.fields.clone())),
        ),
        _ => (native_peer.cloned(), None),
    }
}

async fn log_disposition_impl(args: LogDisposition<'_>, smtp: Option<LocalSmtpDisposition<'_>>) {
    let LogDisposition {
        mut kind,
        msg,
        site,
        peer_address,
        response,
        egress_pool,
        egress_source,
        relay_disposition,
        delivery_protocol,
        tls_info,
        source_address,
        provider,
        session_id,
        recipient_list,
    } = args;

    let loggers = Logger::get_loggers();
    if loggers.is_empty() {
        return;
    }

    msg.load_meta_if_needed().await.ok();

    let recipient_list = match recipient_list {
        Some(list) => list,
        None => msg.recipient_list_string().await.unwrap_or_else(|err| {
            tracing::error!("log_disposition: recipient_list_string: {err:#}");
            vec![]
        }),
    };

    let mut feedback_report = None;

    let reception_protocol = msg
        .get_meta_string("reception_protocol")
        .await
        .unwrap_or(None);

    if kind == RecordType::Reception {
        if relay_disposition
            .as_ref()
            .map(|disp| disp.log_arf.should_log())
            .unwrap_or(false)
        {
            if let Ok(Some(report)) = msg.parse_rfc5965().await {
                feedback_report.replace(Box::new(report));
                kind = RecordType::Feedback;
            }
        }
    }

    let now = Utc::now();
    let nodeid = kumo_server_common::nodeid::NodeId::get_uuid();

    for logger in loggers.iter() {
        if !logger.record_is_enabled(kind) {
            continue;
        }
        if let Some(name) = &logger.filter_event {
            match load_config().await {
                Ok(mut lua_config) => {
                    let log_sig = CallbackSignature::<Message, bool>::new(name.clone());

                    let enqueue: bool =
                        match lua_config.async_call_callback(&log_sig, msg.clone()).await {
                            Ok(b) => {
                                lua_config.put();
                                b
                            }
                            Err(err) => {
                                tracing::error!(
                                    "error while calling {name} event for log filter: {err:#}"
                                );
                                false
                            }
                        };
                    if !enqueue {
                        continue;
                    }
                }
                Err(err) => {
                    tracing::error!(
                        "failed to load lua config while attempting to \
                         call {name} event for log filter: {err:#}"
                    );
                    continue;
                }
            };
        }

        for _ in 0..recipient_list.len() {
            match kind {
                RecordType::Reception => {
                    crate::accounting::account_reception(
                        &reception_protocol.as_deref().unwrap_or("unknown"),
                    );
                }
                RecordType::Delivery => {
                    crate::accounting::account_delivery(
                        &delivery_protocol.as_deref().unwrap_or("unknown"),
                    );
                }
                _ => {}
            };
        }

        let (headers, meta) = logger.extract_fields(&msg).await;

        let mut tls_cipher = None;
        let mut tls_protocol_version = None;
        let mut tls_peer_subject_name = None;
        if let Some(info) = tls_info {
            tls_cipher.replace(info.cipher.clone());
            tls_protocol_version.replace(info.protocol_version.clone());
            tls_peer_subject_name.replace(info.subject_name.clone());
        }

        let (record_peer_address, smtp) =
            disposition_peer_and_smtp(logger.hook_name.as_deref(), peer_address, smtp.as_ref());
        let record = JsonLogRecord {
            kind,
            id: msg.id().to_string(),
            size: msg.get_data_maybe_not_loaded().len() as u64,
            sender: msg
                .sender()
                .await
                .map(|addr| addr.to_string())
                .unwrap_or_else(|err| format!("{err:#}")),
            recipient: recipient_list.clone(),
            queue: msg
                .get_queue_name()
                .await
                .unwrap_or_else(|err| format!("{err:#}")),
            site: site.to_string(),
            peer_address: record_peer_address,
            response: response.clone(),
            timestamp: now,
            created: msg.id().created(),
            num_attempts: msg.get_num_attempts(),
            egress_pool: egress_pool.map(|s| s.to_string()),
            egress_source: egress_source.map(|s| s.to_string()),
            bounce_classification: BounceClass::default(),
            feedback_report: feedback_report.clone(),
            headers: headers.clone(),
            meta: meta.clone(),
            delivery_protocol: delivery_protocol.map(|s| s.to_string()),
            reception_protocol: reception_protocol.clone(),
            nodeid,
            tls_cipher,
            tls_protocol_version,
            tls_peer_subject_name,
            source_address: source_address.clone(),
            provider_name: provider.map(|s| s.to_string()),
            session_id,
            smtp,
        };
        if let Err(err) = logger.log(record, Some(msg.clone())).await {
            tracing::error!("failed to log: {err:#}");
        }

        if kind == RecordType::Reception {
            if relay_disposition
                .as_ref()
                .map(|disp| disp.log_oob.should_log())
                .unwrap_or(false)
            {
                if let Ok(Some(report)) = msg.parse_rfc3464().await {
                    // This incoming bounce report is addressed to
                    // the envelope from of the original message
                    let sender = msg
                        .first_recipient()
                        .await
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|err| format!("{err:#}"));
                    let queue = msg
                        .get_queue_name()
                        .await
                        .unwrap_or_else(|err| format!("{err:#}"));

                    let reconstructed_original_msg = None; // FIXME: try to build this from the
                                                           // parsed rfc3464 report?

                    for recip in &report.per_recipient {
                        if recip.action != ReportAction::Failed {
                            continue;
                        }

                        let enhanced_code = EnhancedStatusCode {
                            class: recip.status.class,
                            subject: recip.status.subject,
                            detail: recip.status.detail,
                        };

                        let (code, content) = match &recip.diagnostic_code {
                            Some(diag) if diag.diagnostic_type == "smtp" => {
                                if let Some((code, content)) = diag.diagnostic.split_once(' ') {
                                    if let Ok(code) = code.parse() {
                                        (code, content.to_string())
                                    } else {
                                        (550, diag.diagnostic.to_string())
                                    }
                                } else {
                                    (550, diag.diagnostic.to_string())
                                }
                            }
                            _ => (550, "".to_string()),
                        };

                        let record = JsonLogRecord {
                            kind: RecordType::OOB,
                            id: msg.id().to_string(),
                            size: 0,
                            sender: sender.clone(),
                            recipient: vec![recip
                                .original_recipient
                                .as_ref()
                                .unwrap_or(&recip.final_recipient)
                                .recipient
                                .to_string()],
                            queue: queue.to_string(),
                            site: site.to_string(),
                            peer_address: Some(ResolvedAddress {
                                name: report.per_message.reporting_mta.name.to_string(),
                                addr: peer_address
                                    .map(|a| a.addr.clone())
                                    .unwrap_or_else(|| Ipv4Addr::UNSPECIFIED.into()),
                                is_secure: false,
                            }),
                            response: Response {
                                code,
                                enhanced_code: Some(enhanced_code),
                                content,
                                command: None,
                            },
                            timestamp: recip.last_attempt_date.unwrap_or_else(|| Utc::now()),
                            created: msg.id().created(),
                            num_attempts: 0,
                            egress_pool: None,
                            egress_source: None,
                            bounce_classification: BounceClass::default(),
                            feedback_report: None,
                            headers: headers.clone(),
                            meta: meta.clone(),
                            delivery_protocol: None,
                            reception_protocol: reception_protocol.clone(),
                            nodeid,
                            tls_cipher: None,
                            tls_protocol_version: None,
                            tls_peer_subject_name: None,
                            source_address: None,
                            provider_name: provider.map(|s| s.to_string()),
                            session_id,
                            smtp: None,
                        };

                        if let Err(err) =
                            logger.log(record, reconstructed_original_msg.clone()).await
                        {
                            tracing::error!("failed to log: {err:#}");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn saved_transaction_peer_and_smtp_fields_are_local_only() {
        let peer = ResolvedAddress {
            name: "mx.example".into(),
            addr: Ipv4Addr::new(192, 0, 2, 1).into(),
            is_secure: false,
        };
        let fields = SmtpDispositionFields {
            transaction_number: Some(7),
            ..Default::default()
        };
        let saved = LocalSmtpDisposition {
            fields: &fields,
            peer_address: Some(&peer),
        };

        // A generic post-transaction error has no native peer. Both queued
        // and immediate hooks are named; only the local file logger is unnamed.
        let (addr, smtp) = disposition_peer_and_smtp(None, None, Some(&saved));
        assert_eq!(addr.as_ref(), Some(&peer));
        assert_eq!(smtp.as_deref(), Some(&fields));
        assert_eq!(
            disposition_peer_and_smtp(Some("hook"), None, Some(&saved)),
            (None, None)
        );

        // A normal SMTP disposition already knows its peer in every sink.
        let normal = LocalSmtpDisposition {
            peer_address: None,
            ..saved
        };
        let (addr, smtp) = disposition_peer_and_smtp(None, Some(&peer), Some(&normal));
        assert_eq!(addr.as_ref(), Some(&peer));
        assert_eq!(smtp.as_deref(), Some(&fields));
        let (addr, smtp) = disposition_peer_and_smtp(Some("hook"), Some(&peer), Some(&normal));
        assert_eq!(addr.as_ref(), Some(&peer));
        assert!(smtp.is_none());
    }
}
