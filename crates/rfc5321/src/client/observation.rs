use super::{ClientError, Command, Instant, Response};
use std::time::Duration;

#[cfg(test)]
mod tests;

/// An operation on the SMTP connection, without command arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpStage {
    Banner,
    Ehlo,
    StartTls,
    Auth,
    Rset,
    MailFrom,
    RcptTo,
    Data,
    DataWrite,
    DataDot,
    Pipeline,
    Unilateral,
    Other,
}

impl SmtpStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Banner => "banner",
            Self::Ehlo => "ehlo",
            Self::StartTls => "starttls",
            Self::Auth => "auth",
            Self::Rset => "rset",
            Self::MailFrom => "mail_from",
            Self::RcptTo => "rcpt_to",
            Self::Data => "data",
            Self::DataWrite => "data_write",
            Self::DataDot => "data_dot",
            Self::Pipeline => "pipeline",
            Self::Unilateral => "unilateral",
            Self::Other => "other",
        }
    }
}

impl From<&Command> for SmtpStage {
    fn from(command: &Command) -> Self {
        match command {
            Command::Ehlo(_) | Command::Helo(_) | Command::Lhlo(_) => Self::Ehlo,
            Command::StartTls => Self::StartTls,
            Command::Auth { .. } => Self::Auth,
            Command::Rset => Self::Rset,
            Command::MailFrom { .. } => Self::MailFrom,
            Command::RcptTo { .. } => Self::RcptTo,
            Command::Data => Self::Data,
            Command::DataDot => Self::DataDot,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpFailureKind {
    SmtpReply,
    ResponseTimeout,
    WriteTimeout,
    Disconnect,
    ProtocolError,
    TlsError,
    LocalError,
}

impl SmtpFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmtpReply => "smtp_reply",
            Self::ResponseTimeout => "response_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::Disconnect => "disconnect",
            Self::ProtocolError => "protocol_error",
            Self::TlsError => "tls_error",
            Self::LocalError => "local_error",
        }
    }
}

/// Structured observations from one client. No command arguments, envelope
/// or message data are included. `PeerReply` text is untrusted classifier
/// input; a consumer must apply its privacy policy before logging it.
#[derive(Debug)]
pub enum SmtpObservation {
    /// One complete negative reply, before disposition selection or rewrites.
    /// The command is always absent. AUTH and unrecognized stages omit text.
    /// Other text is limited to 1,024 UTF-8 bytes; `truncated` means the
    /// prefix must not be treated as a complete reply for classification.
    PeerReply {
        stage: SmtpStage,
        response: Response,
        truncated: bool,
    },
    /// A completed banner, greeting, TLS negotiation, or authentication step.
    Phase {
        stage: SmtpStage,
        duration: Duration,
        failure: Option<SmtpFailureKind>,
    },
    /// A MAIL FROM write is beginning (possibly as part of a pipeline).
    MailFromStarted,
    /// One send operation that reached MAIL FROM, not one event per recipient.
    TransactionFinished {
        duration: Duration,
        stage: SmtpStage,
        failure: Option<SmtpFailureKind>,
    },
    BeforeMailFromFailure {
        stage: SmtpStage,
        failure: SmtpFailureKind,
    },
}

/// Called inline, in wire order. Implementations must not block and should
/// bound any retained diagnostics separately from counting the observations.
pub trait SmtpClientObserver: std::fmt::Debug + Send + Sync {
    fn observe(&self, event: SmtpObservation);
}

impl SmtpObservation {
    pub(super) fn peer_reply(stage: SmtpStage, reply: &Response) -> Self {
        const MAX_PEER_TEXT: usize = 1024;
        // A caller may have issued an unparsed command via Command::Unknown;
        // in that case we cannot rule out a credential-bearing exchange.
        let (content, truncated) = if matches!(stage, SmtpStage::Auth | SmtpStage::Other) {
            (String::new(), false)
        } else {
            let end = reply.content.floor_char_boundary(MAX_PEER_TEXT);
            (reply.content[..end].to_owned(), end < reply.content.len())
        };
        Self::PeerReply {
            stage,
            response: Response {
                code: reply.code,
                enhanced_code: reply.enhanced_code,
                content,
                command: None,
            },
            truncated,
        }
    }
}

/// Keep the typed operation alongside its error until the send operation has
/// selected its terminal disposition. In particular, synthesized pipeline
/// results must not relabel a batch write as the first command's reply.
#[derive(Clone)]
pub(super) struct WireError {
    pub stage: SmtpStage,
    pub kind: SmtpFailureKind,
    pub error: ClientError,
}

impl WireError {
    pub fn new(stage: SmtpStage, error: ClientError) -> Self {
        use SmtpFailureKind::*;
        let kind = match &error {
            // Only the transport code that actually read a reply may assign
            // SmtpReply. A locally generated Rejected is still a local error.
            ClientError::Rejected(_) | ClientError::RejectedBatch(_) => LocalError,
            ClientError::TimeOutResponse { .. } => ResponseTimeout,
            ClientError::TimeOutData | ClientError::TimeOutRequest { .. } => WriteTimeout,
            ClientError::ReadError { .. }
            | ClientError::WriteError { .. }
            | ClientError::FlushError { .. }
            | ClientError::NotConnected => Disconnect,
            ClientError::Utf8(_)
            | ClientError::MalformedResponseLine(_)
            | ClientError::ResponseTooLong => ProtocolError,
            ClientError::FailedToBuildConnector { .. }
            | ClientError::NoUsableDaneTlsa { .. }
            | ClientError::SslErrorStack(_) => TlsError,
            ClientError::InvalidDnsName(_) => LocalError,
        };
        Self { stage, kind, error }
    }

    pub fn rejected(stage: SmtpStage, response: Response) -> Self {
        Self {
            stage,
            kind: Self::reply_failure(&response),
            error: ClientError::Rejected(response),
        }
    }

    pub fn rejected_batch(responses: Vec<Response>) -> Self {
        let has_refusal = responses.iter().any(|r| (400..600).contains(&r.code));
        Self {
            stage: SmtpStage::RcptTo,
            kind: if has_refusal {
                SmtpFailureKind::SmtpReply
            } else {
                SmtpFailureKind::ProtocolError
            },
            error: ClientError::RejectedBatch(responses),
        }
    }

    pub fn reply_failure(response: &Response) -> SmtpFailureKind {
        if (400..600).contains(&response.code) {
            SmtpFailureKind::SmtpReply
        } else {
            SmtpFailureKind::ProtocolError
        }
    }
}

#[derive(Default)]
pub(super) struct TransactionTimer {
    pub started: Option<Instant>,
    pub finished: Option<Instant>,
}

impl TransactionTimer {
    pub fn mark_end(&mut self) {
        self.finished = self.started.map(|_| Instant::now());
    }
}
