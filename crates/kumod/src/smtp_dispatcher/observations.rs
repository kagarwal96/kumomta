//! Outbound observations are separate from delivery decisions. A plan may span
//! several sockets; only a socket that reached SMTP-ready has a connection ID.
use super::{Dispatcher, MxListEntry, SmtpProtocol};
use crate::logging::log_smtp_connection_plan;
use crate::smtp_telemetry as metrics;
use kumo_api_types::egress_path::EgressPathConfig;
use kumo_log_types::smtp::{
    SmtpAddressList, SmtpConnectionPlan, SmtpDiscovery, SmtpDispositionFields, SmtpPeerReply,
    SmtpPeerResponse, SmtpSetupAttempt, SmtpSetupPhase,
};
use kumo_log_types::ResolvedAddress;
use mailexchanger::AddressListStats;
use parking_lot::Mutex;
use rfc5321::{Response, SmtpClientObserver, SmtpFailureKind, SmtpObservation, SmtpStage};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

// Limits apply to diagnostics, not to metric observations or the delivery plan.
const MAX_ATTEMPTS: usize = 16;
const MAX_PHASES: usize = 16;
const MAX_REPLIES: usize = 8;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.
}

#[derive(Debug)]
pub(super) struct Plan {
    provider: String,
    discovery: SmtpDiscovery,
    address_list: Option<SmtpAddressList>,
    build_duration: Option<Duration>,
    first_dial: Option<Instant>,
    attempts: Vec<Attempt>,
    attempt_count: usize,
    tcp_candidates: usize,
    failed: bool,
    pub socket: Option<Arc<SocketObserver>>,
}

impl Plan {
    pub fn new(dispatcher: &Dispatcher, config: &SmtpProtocol, path: &EgressPathConfig) -> Self {
        let (provider, method) = if let Some(mx) = &dispatcher.mx {
            (
                metrics::plan_provider(mx.hosts.iter().map(String::as_str)),
                if mx.is_domain_literal {
                    "literal"
                } else if mx.is_mx {
                    "mx"
                } else {
                    "implicit_mx"
                },
            )
        } else {
            (
                metrics::plan_provider(config.mx_list.iter().map(MxListEntry::hostname)),
                "mx_list",
            )
        };
        let mta_sts = match (
            path.enable_mta_sts,
            dispatcher.mx.as_ref().map(|mx| mx.mta_sts),
        ) {
            (false, _) => "disabled",
            (_, Some(mailexchanger::PolicyMode::Enforce)) => "enforce",
            (_, Some(mailexchanger::PolicyMode::Testing)) => "testing",
            _ => "none",
        };
        Self {
            provider,
            discovery: SmtpDiscovery {
                method: method.into(),
                mta_sts: Some(mta_sts.into()),
                dane: Some(
                    if path.enable_dane {
                        "enabled"
                    } else {
                        "disabled"
                    }
                    .into(),
                ),
            },
            address_list: None,
            build_duration: None,
            first_dial: None,
            attempts: vec![],
            attempt_count: 0,
            tcp_candidates: 0,
            failed: false,
            socket: None,
        }
    }

    pub fn built(&mut self, stats: AddressListStats, candidates: usize) {
        self.build_duration = stats.first_lookup.map(|start| start.elapsed());
        let outcome = stats.outcome(candidates);
        if let Some(duration) = self.build_duration {
            metrics::address_list(outcome, duration);
        }
        self.address_list = Some(SmtpAddressList {
            outcome: outcome.into(),
            address_list_build_ms: self.build_duration.map(ms),
            mx_hosts_looked_up: Some(stats.mx_hosts_looked_up as u64),
            usable_ip_candidates: Some(candidates as u64),
        });
    }

    pub fn new_socket(
        &mut self,
        address: &ResolvedAddress,
        dispatcher: &Dispatcher,
    ) -> Arc<SocketObserver> {
        let pref = dispatcher.mx.as_ref().and_then(|mx| {
            mx.by_pref.iter().find_map(|(p, hosts)| {
                hosts
                    .iter()
                    .any(|h| {
                        let host =
                            dns_resolver::has_colon_port(h).map_or(h.as_str(), |(name, _)| name);
                        host == address.name
                    })
                    .then_some(*p)
            })
        });
        let socket = Arc::new(SocketObserver {
            provider: metrics::provider(&address.name).into(),
            mx: address.name.clone(),
            ip: address.addr.ip(),
            preference: pref,
            state: Mutex::default(),
        });
        self.socket = Some(socket.clone());
        socket
    }

    // Called immediately after the candidate result, before the ready queue can
    // try its successor. Cancellation is not a completed candidate or plan.
    pub async fn attempt_result(&mut self, dispatcher: &Dispatcher, ready: bool, exhausted: bool) {
        let end = Instant::now();
        let Some(socket) = self.socket.clone() else {
            // E.g. the final candidate failed local TLS certificate preparation
            // before a socket could be attempted.
            if exhausted && (self.attempt_count != 0 || self.address_list.is_some()) {
                self.log(dispatcher, "exhausted", None, Some(end), true)
                    .await;
            }
            return;
        };
        let (tcp, unix, phases, failed_phase, omitted, replies) = {
            let mut state = socket.state.lock();
            (
                state.first_dial,
                state.unix_dial,
                std::mem::take(&mut state.phases),
                state.failed_phase,
                state.phases_omitted,
                std::mem::take(&mut state.replies),
            )
        };
        if let Some(start) = tcp {
            self.first_dial.get_or_insert(start);
            if self.tcp_candidates == 0 {
                metrics::first_candidate(&socket.provider, ready);
            }
            self.tcp_candidates += 1;
        }
        let setup = self.first_dial.map(|start| end.duration_since(start));
        let id = ready.then(|| socket.mark_ready(setup));
        let refused = !replies.items.is_empty() || replies.omitted != 0;
        self.failed |= !ready || refused || failed_phase;
        if let Some(start) = tcp.or(unix) {
            self.attempt_count += 1;
            let record = SmtpSetupAttempt {
                mx: socket.mx.clone(),
                ip: socket.ip,
                preference: socket.preference,
                elapsed_ms: Some(ms(end.duration_since(start))),
                outcome: if ready { "smtp_ready" } else { "failed" }.into(),
                phases,
                phases_omitted: None,
            };
            // Retain the final endpoint even when earlier attempts overflow. Do
            // not call Lua between attempts or charge its time to SMTP setup.
            if self.attempts.len() == MAX_ATTEMPTS {
                self.attempts.pop();
            }
            self.attempts.push(Attempt {
                record,
                omitted,
                replies,
            });
        }
        if !ready {
            self.socket.take();
        }
        if ready || exhausted {
            let result = if !ready {
                "exhausted"
            } else if self.failed {
                "recovered"
            } else {
                "ready"
            };
            self.log(dispatcher, result, id, Some(end), self.failed)
                .await;
        }
    }

    pub async fn log(
        &mut self,
        dispatcher: &Dispatcher,
        result: &'static str,
        id: Option<Uuid>,
        end: Option<Instant>,
        failed: bool,
    ) {
        let duration = self
            .first_dial
            .take()
            .zip(end)
            .map(|(s, e)| e.duration_since(s));
        if let Some(d) = duration {
            metrics::setup(&self.provider, id.is_some(), self.tcp_candidates, d);
        }
        let mut attempts = vec![];
        for attempt in std::mem::take(&mut self.attempts) {
            attempts.push(attempt.record().await);
        }
        let record = SmtpConnectionPlan {
            session_id: dispatcher.session_id,
            connection_id: id,
            egress_source: Some(dispatcher.egress_source.name.to_string()),
            route: None,
            result: result.into(),
            discovery: Some(self.discovery.clone()),
            address_list: self.address_list.take(),
            connection_setup_ms: duration.map(ms),
            attempts_omitted: Some((self.attempt_count - attempts.len()) as u64),
            attempts,
        };
        self.attempt_count = 0;
        self.tcp_candidates = 0;
        self.failed = false;
        log_smtp_connection_plan(record, failed, self.build_duration.take(), duration).await;
    }
}

#[derive(Debug)]
struct Attempt {
    record: SmtpSetupAttempt,
    omitted: usize,
    replies: Replies,
}

impl Attempt {
    async fn record(mut self) -> SmtpSetupAttempt {
        let phases = &mut self.record.phases;
        self.omitted += self.replies.omitted;
        for mut reply in self.replies.items {
            let clean = reply.classify().await;
            let phase = reply.stage.as_str();
            if let Some(step) = phases
                .get_mut(reply.phase_index)
                .filter(|step| step.phase.as_str() == phase && step.response.is_none())
            {
                step.response = Some(clean);
                step.failure_kind = Some("smtp_reply".into());
            } else if phases.len() < MAX_PHASES {
                phases.push(SmtpSetupPhase {
                    phase: phase.into(),
                    outcome: "error".into(),
                    elapsed_ms: None,
                    failure_kind: Some("smtp_reply".into()),
                    response: Some(clean),
                });
            } else {
                self.omitted += 1;
            }
        }
        // Some local policy or setup errors occur between wire operations.
        // Do not assign them to the last successful SMTP command.
        if self.record.outcome.as_str() == "failed"
            && !phases.iter().any(|step| step.outcome.as_str() == "error")
        {
            if phases.len() < MAX_PHASES {
                phases.push(SmtpSetupPhase {
                    phase: "other".into(),
                    outcome: "error".into(),
                    elapsed_ms: None,
                    failure_kind: Some("local_error".into()),
                    response: None,
                });
            } else {
                self.omitted += 1;
            }
        }
        self.record.phases_omitted = (self.omitted > 0).then_some(self.omitted as u64);
        self.record
    }
}

struct PendingReply {
    provider: Arc<str>,
    stage: SmtpStage,
    phase_index: usize,
    response: Response,
    truncated: bool,
    counted: bool,
}

impl PendingReply {
    fn matches(&self, stage: SmtpStage, native: &Response) -> bool {
        self.stage == stage
            && self.response.code == native.code
            && self.response.enhanced_code == native.enhanced_code
            && (if self.truncated {
                native.content.starts_with(&self.response.content)
            } else {
                native.content == self.response.content
            })
    }

    async fn classify(&mut self) -> SmtpPeerResponse {
        if self.truncated {
            self.response.content.clear();
        }
        // peer_reply increments after classification, with no subsequent await.
        let mut clean =
            metrics::peer_reply(&self.provider, self.stage.as_str(), &self.response).await;
        self.counted = true;
        if self.truncated {
            clean.content_truncated = Some(true);
        }
        clean
    }
}

impl Drop for PendingReply {
    fn drop(&mut self) {
        // Covers unprocessed observations when the payload is capped or the
        // dispatcher shuts down before the classifier returns.
        if !self.counted {
            metrics::peer_reply_unclassified(&self.provider, &self.response);
        }
    }
}

#[derive(Default)]
struct Replies {
    items: Vec<PendingReply>,
    omitted: usize,
}

impl std::fmt::Debug for Replies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replies")
            .field("retained", &self.items.len())
            .field("omitted", &self.omitted)
            .finish()
    }
}

struct ReadySocket {
    id: Uuid,
    setup: Option<Duration>,
    attempted: u64,
    accepted: u64,
}

#[derive(Default)]
struct State {
    first_dial: Option<Instant>,
    unix_dial: Option<Instant>,
    phases: Vec<SmtpSetupPhase>,
    failed_phase: bool,
    phases_omitted: usize,
    ready: Option<ReadySocket>,
    terminal: Option<(SmtpStage, Option<SmtpFailureKind>, Option<Duration>)>,
    replies: Replies,
}

pub(super) struct SocketObserver {
    provider: Arc<str>,
    mx: String,
    ip: Option<IpAddr>,
    preference: Option<u16>,
    state: Mutex<State>,
}

// Do not expose buffered classifier input through dispatcher debug output.
impl std::fmt::Debug for SocketObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketObserver")
            .field("mx", &self.mx)
            .field("ip", &self.ip)
            .finish_non_exhaustive()
    }
}

impl Drop for SocketObserver {
    fn drop(&mut self) {
        if let Some(ready) = self.state.get_mut().ready.take() {
            metrics::connection_closed(&self.provider, ready.attempted, ready.accepted);
        }
    }
}

impl SocketObserver {
    fn mark_ready(&self, setup: Option<Duration>) -> Uuid {
        let id = Uuid::new_v4();
        self.state.lock().ready = Some(ReadySocket {
            id,
            setup,
            attempted: 0,
            accepted: 0,
        });
        id
    }

    pub fn unix_dial(&self) {
        self.state.lock().unix_dial = Some(Instant::now());
    }

    pub fn tcp(&self, start: Instant, result: Option<Result<(), ErrorKind>>) {
        self.state.lock().first_dial.get_or_insert(start);
        if let Some(result) = result {
            self.phase(
                "tcp_connect",
                start.elapsed(),
                result.err().map(|kind| match kind {
                    ErrorKind::TimedOut => "connect_timeout",
                    ErrorKind::ConnectionRefused => "connect_refused",
                    _ => "connect_error",
                }),
            );
        }
    }

    fn phase(&self, phase: &'static str, duration: Duration, failure: Option<&'static str>) {
        metrics::phase(&self.provider, phase, failure.is_none(), duration);
        let mut state = self.state.lock();
        state.failed_phase |= failure.is_some();
        if state.phases.len() < MAX_PHASES {
            state.phases.push(SmtpSetupPhase {
                phase: phase.into(),
                elapsed_ms: Some(ms(duration)),
                outcome: if failure.is_none() { "ok" } else { "error" }.into(),
                failure_kind: failure.map(Into::into),
                response: None,
            });
        } else {
            state.phases_omitted += 1;
        }
    }

    pub async fn drain_idle(&self) {
        let replies = std::mem::take(&mut self.state.lock().replies);
        for mut reply in replies.items {
            reply.classify().await;
        }
    }

    pub async fn delivery(
        &self,
        responses: &[Response],
        policy_veto: bool,
        peer_address: Option<&ResolvedAddress>,
    ) -> Transaction {
        let (terminal, ready, replies) = {
            let mut state = self.state.lock();
            (
                state.terminal.take(),
                state.ready.as_ref().map(|r| (r.id, r.setup, r.attempted)),
                std::mem::take(&mut state.replies),
            )
        };
        let mut fields = SmtpDispositionFields::default();
        let terminal = if policy_veto {
            Some((SmtpStage::Other, Some(SmtpFailureKind::LocalError), None))
        } else {
            terminal
        };
        if let Some((id, setup, number)) = ready {
            fields.connection_id = Some(id);
            if let Some((_, failure, Some(duration))) = terminal {
                let outcome = match failure {
                    None => "accepted",
                    Some(SmtpFailureKind::SmtpReply)
                        if responses.iter().any(|r| (400..500).contains(&r.code)) =>
                    {
                        "deferred"
                    }
                    Some(SmtpFailureKind::SmtpReply) => "bounced",
                    _ => "transport_error",
                };
                metrics::transaction_completed(&self.provider, outcome, duration);
                fields.transaction_number = Some(number);
                fields.transaction_elapsed_ms = Some(ms(duration));
                fields.connection_setup_ms = setup.filter(|_| number == 1).map(ms);
            }
        }
        let failure = terminal.and_then(|(stage, failure, _)| failure.map(|kind| (stage, kind)));
        // Match before any status rewrite. A successful final dot may coexist
        // with rejected RCPTs; their dispositions have individual primary replies.
        let per_recipient = responses
            .iter()
            .map(|response| {
                let stage = match terminal {
                    Some((stage, Some(SmtpFailureKind::SmtpReply), _)) => Some(stage),
                    Some((_, None, Some(_)))
                        if response.is_transient() || response.is_permanent() =>
                    {
                        Some(SmtpStage::RcptTo)
                    }
                    _ => None,
                };
                let primary = stage.and_then(|s| {
                    replies
                        .items
                        .iter()
                        .position(|reply| reply.matches(s, response))
                        .map(Primary::Retained)
                        // Even beyond the payload cap, keep the numeric peer status
                        // of this recipient, never its unchecked text or command.
                        .or_else(|| {
                            (replies.omitted != 0 && (400..600).contains(&response.code))
                                .then_some(Primary::Omitted(response.code, response.enhanced_code))
                        })
                });
                (stage, primary)
            })
            .collect();
        let mut clean = vec![];
        for mut reply in replies.items {
            clean.push(SmtpPeerReply {
                smtp_stage: reply.stage.as_str().into(),
                response: reply.classify().await,
            });
        }
        Transaction {
            peer_address: peer_address.cloned(),
            fields,
            per_recipient,
            failure,
            replies: clean,
            omitted: replies.omitted,
        }
    }
}

impl SmtpClientObserver for SocketObserver {
    fn observe(&self, event: SmtpObservation) {
        match event {
            SmtpObservation::PeerReply {
                stage,
                response,
                truncated,
            } => {
                let mut state = self.state.lock();
                let phase_index = state.phases.len();
                if state.replies.items.len() == MAX_REPLIES {
                    state.replies.omitted += 1;
                    metrics::peer_reply_unclassified(&self.provider, &response);
                } else {
                    state.replies.items.push(PendingReply {
                        provider: self.provider.clone(),
                        stage,
                        phase_index,
                        response,
                        truncated,
                        counted: false,
                    });
                }
            }
            SmtpObservation::Phase {
                stage,
                duration,
                failure,
            } => self.phase(stage.as_str(), duration, failure.map(|k| k.as_str())),
            SmtpObservation::MailFromStarted => {
                if let Some(r) = self.state.lock().ready.as_mut() {
                    r.attempted += 1;
                    metrics::transaction_started(&self.provider, r.attempted == 1);
                }
            }
            SmtpObservation::TransactionFinished {
                duration,
                stage,
                failure,
            } => {
                let mut state = self.state.lock();
                state.terminal = Some((stage, failure, Some(duration)));
                if failure.is_none() {
                    if let Some(r) = state.ready.as_mut() {
                        r.accepted += 1;
                    }
                }
            }
            SmtpObservation::BeforeMailFromFailure { stage, failure } => {
                self.state.lock().terminal = Some((stage, Some(failure), None))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Primary {
    Retained(usize),
    Omitted(u16, Option<rfc5321::EnhancedStatusCode>),
}

pub(crate) struct Transaction {
    pub(crate) peer_address: Option<ResolvedAddress>,
    fields: SmtpDispositionFields,
    per_recipient: Vec<(Option<SmtpStage>, Option<Primary>)>,
    failure: Option<(SmtpStage, SmtpFailureKind)>,
    replies: Vec<SmtpPeerReply>,
    omitted: usize,
}

impl Transaction {
    pub(crate) fn internal_error_fields(&self) -> SmtpDispositionFields {
        SmtpDispositionFields {
            smtp_stage: Some("other".into()),
            failure_kind: Some("local_error".into()),
            peer_replies: self.replies.clone(),
            peer_replies_omitted: (self.omitted > 0).then_some(self.omitted as u64),
            ..self.fields.clone()
        }
    }

    pub fn fields(&self, recipient: usize) -> SmtpDispositionFields {
        let mut fields = self.fields.clone();
        let (stage, primary) = self.per_recipient[recipient];
        if let Some((stage, kind)) = self
            .failure
            .or_else(|| stage.map(|s| (s, SmtpFailureKind::SmtpReply)))
        {
            fields.smtp_stage = Some(stage.as_str().into());
            fields.failure_kind = Some(kind.as_str().into());
        }
        let mut omitted = self.omitted;
        let primary_index = match primary {
            Some(Primary::Retained(i)) => {
                fields.peer_response = Some(self.replies[i].response.clone());
                Some(i)
            }
            Some(Primary::Omitted(code, dsn)) => {
                fields.peer_response = Some(SmtpPeerResponse::new(code, dsn));
                omitted -= 1;
                None
            }
            None => None,
        };
        fields.peer_replies = self
            .replies
            .iter()
            .enumerate()
            .filter_map(|(i, r)| (Some(i) != primary_index).then_some(r))
            .cloned()
            .collect();
        fields.peer_replies_omitted = (omitted > 0).then_some(omitted as u64);
        fields
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{json, to_value};

    fn socket() -> SocketObserver {
        SocketObserver {
            provider: "other".into(),
            mx: "mx.example".into(),
            ip: None,
            preference: None,
            state: Mutex::default(),
        }
    }

    fn reply(code: u16) -> Response {
        Response {
            code,
            enhanced_code: None,
            command: None,
            content: String::new(),
        }
    }

    fn negative(socket: &SocketObserver, stage: SmtpStage, code: u16) {
        socket.observe(SmtpObservation::PeerReply {
            stage,
            response: reply(code),
            truncated: false,
        });
    }

    fn finish(socket: &SocketObserver, stage: SmtpStage, failure: Option<SmtpFailureKind>) {
        socket.observe(SmtpObservation::TransactionFinished {
            duration: Duration::from_millis(3),
            stage,
            failure,
        });
    }

    #[tokio::test]
    async fn primary_refusal_and_setup_time_stay_on_first_transaction() {
        let socket = socket();
        let id = socket.mark_ready(Some(Duration::from_millis(7)));
        socket.observe(SmtpObservation::MailFromStarted);
        negative(&socket, SmtpStage::MailFrom, 450);
        negative(&socket, SmtpStage::Data, 503);
        finish(
            &socket,
            SmtpStage::MailFrom,
            Some(SmtpFailureKind::SmtpReply),
        );
        let first = to_value(socket.delivery(&[reply(450)], false, None).await.fields(0)).unwrap();
        assert_eq!(first["connection_id"], json!(id));
        assert_eq!(first["connection_setup_ms"], 7.0);
        assert_eq!(first["transaction_elapsed_ms"], 3.0);
        assert_eq!(first["transaction_number"], 1);
        assert_eq!(first["smtp_stage"], "mail_from");
        assert_eq!(first["peer_response"]["code"], 450);
        assert_eq!(first["peer_replies"][0]["smtp_stage"], "data");
        assert_eq!(first["peer_replies"][0]["response"]["code"], 503);

        socket.observe(SmtpObservation::MailFromStarted);
        finish(&socket, SmtpStage::DataDot, None);
        let reused = to_value(socket.delivery(&[reply(250)], false, None).await.fields(0)).unwrap();
        assert_eq!(reused["connection_id"], json!(id));
        assert_eq!(reused["transaction_number"], 2);
        assert_eq!(reused["transaction_elapsed_ms"], 3.0);
        assert!(reused.get("connection_setup_ms").is_none());
        assert!(reused.get("peer_response").is_none());
        let state = socket.state.lock();
        let ready = state.ready.as_ref().unwrap();
        assert_eq!((ready.attempted, ready.accepted), (2, 1));
    }

    #[tokio::test]
    async fn pre_mail_veto_has_no_transaction_timing_or_peer_reply() {
        let socket = socket();
        socket.mark_ready(Some(Duration::from_millis(7)));
        let veto = to_value(socket.delivery(&[reply(451)], true, None).await.fields(0)).unwrap();
        assert_eq!(veto["failure_kind"], "local_error");
        assert!(veto.get("transaction_number").is_none());
        assert!(veto.get("transaction_elapsed_ms").is_none());
        assert!(veto.get("connection_setup_ms").is_none());
        assert!(veto.get("peer_response").is_none());
    }

    #[tokio::test]
    async fn mixed_recipients_keep_their_own_primary_reply_across_payload_limit() {
        let socket = socket();
        socket.mark_ready(None);
        socket.observe(SmtpObservation::MailFromStarted);
        for _ in 0..MAX_REPLIES {
            negative(&socket, SmtpStage::RcptTo, 450);
        }
        negative(&socket, SmtpStage::RcptTo, 551);
        finish(&socket, SmtpStage::DataDot, None);
        let report = socket
            .delivery(&[reply(250), reply(551)], false, None)
            .await;
        let accepted = to_value(report.fields(0)).unwrap();
        let refused = to_value(report.fields(1)).unwrap();
        assert!(accepted.get("peer_response").is_none());
        assert!(accepted.get("failure_kind").is_none());
        assert_eq!(accepted["peer_replies_omitted"], 1);
        assert_eq!(refused["failure_kind"], "smtp_reply");
        assert_eq!(refused["smtp_stage"], "rcpt_to");
        assert_eq!(refused["peer_response"]["code"], 551);
        assert_eq!(
            refused["peer_replies"].as_array().unwrap().len(),
            MAX_REPLIES
        );
        assert!(refused.get("peer_replies_omitted").is_none());
        assert_eq!(
            refused["transaction_number"],
            accepted["transaction_number"]
        );
    }

    #[tokio::test]
    async fn address_list_stats_for_mixed_mx_list() {
        use dns_resolver::{IpLookupStrategy, TestResolver};

        let resolver = TestResolver::default().with_bogus("broken.example.");
        let mut addresses = vec![];
        let mut stats = AddressListStats::default();
        for entry in [
            MxListEntry::Name("[192.0.2.1]:2525".into()),
            MxListEntry::Name("/tmp/smtp.sock".into()),
            MxListEntry::Resolved(ResolvedAddress {
                name: "relay.example".into(),
                addr: "192.0.2.2".parse().unwrap(),
                is_secure: false,
            }),
        ] {
            entry
                .resolve_into(
                    &mut addresses,
                    Some(&resolver),
                    IpLookupStrategy::Ipv4Only,
                    10,
                    Some(&mut stats),
                )
                .await
                .unwrap();
        }
        assert_eq!(addresses.len(), 3);
        assert_eq!(stats.mx_hosts_looked_up, 0);
        assert!(stats.first_lookup.is_none());
        assert_eq!(stats.outcome(addresses.len()), "complete");

        // The failed DNS entry starts the timer; the local candidates still
        // make this a partial list, not a no-address result.
        MxListEntry::Name("broken.example.".into())
            .resolve_into(
                &mut addresses,
                Some(&resolver),
                IpLookupStrategy::Ipv4Only,
                10,
                Some(&mut stats),
            )
            .await
            .unwrap_err();
        assert_eq!(addresses.len(), 3);
        assert_eq!(stats.mx_hosts_looked_up, 1);
        assert!(stats.first_lookup.is_some());
        assert_eq!(stats.outcome(addresses.len()), "partial");
    }
}
