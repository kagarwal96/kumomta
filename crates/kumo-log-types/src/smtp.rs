//! Diagnostics for the local outbound SMTP logs. These structures deliberately
//! have no catch-all map: a diagnostic cannot replace disposition fields or
//! introduce a command, envelope or message into a connection plan.
use chrono::{DateTime, Utc};
use rfc5321::EnhancedStatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use std::net::IpAddr;
use uuid::Uuid;

/// A step, outcome or other short label supplied by the SMTP client; never a
/// command with arguments or an error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SmtpLogLabel(String);

impl SmtpLogLabel {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for SmtpLogLabel {
    fn from(label: &'static str) -> Self {
        Self::try_from(label.to_owned()).unwrap_or_else(|_| Self("other".into()))
    }
}

impl TryFrom<String> for SmtpLogLabel {
    type Error = &'static str;

    fn try_from(label: String) -> Result<Self, Self::Error> {
        if label.is_empty()
            || label.len() > 48
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("expected a short SMTP label");
        }
        Ok(Self(label))
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpPeerResponse {
    #[serde(deserialize_with = "negative_code")]
    pub code: u16,
    pub enhanced_code: Option<EnhancedStatusCode>,
    pub reason: Option<SmtpLogLabel>,
    /// Policy-approved text, not the native SMTP response content.
    pub content: Option<String>,
    pub content_truncated: Option<bool>,
}

fn negative_code<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
    let code = u16::deserialize(d)?;
    if (400..600).contains(&code) {
        Ok(code)
    } else {
        Err(serde::de::Error::custom(
            "expected a negative SMTP reply code",
        ))
    }
}

impl SmtpPeerResponse {
    pub fn new(code: u16, enhanced_code: Option<EnhancedStatusCode>) -> Self {
        Self {
            code,
            enhanced_code,
            reason: None,
            content: None,
            content_truncated: None,
        }
    }

    fn limit(&mut self, stage: Option<&SmtpLogLabel>) {
        // AUTH exchanges and unrecognized stages have no loggable text.
        if !matches!(
            stage.map(SmtpLogLabel::as_str),
            Some(
                "banner"
                    | "ehlo"
                    | "starttls"
                    | "rset"
                    | "mail_from"
                    | "rcpt_to"
                    | "data"
                    | "data_dot"
                    | "unilateral"
            )
        ) || self
            .content
            .as_ref()
            .is_some_and(|s| s.chars().any(char::is_control))
        {
            self.content = None;
        } else if let Some(s) = &mut self.content {
            if s.len() > 256 {
                s.truncate(s.floor_char_boundary(256));
                self.content_truncated = Some(true);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmtpPeerReply {
    pub smtp_stage: SmtpLogLabel,
    pub response: SmtpPeerResponse,
}

/// Fields added to a message disposition. `response` on the disposition
/// remains the native result, which may have been synthesized or rewritten.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SmtpDispositionFields {
    pub connection_id: Option<Uuid>,
    pub transaction_number: Option<u64>,
    pub transaction_elapsed_ms: Option<f64>,
    pub connection_setup_ms: Option<f64>,
    pub smtp_stage: Option<SmtpLogLabel>,
    pub failure_kind: Option<SmtpLogLabel>,
    pub peer_response: Option<SmtpPeerResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_replies: Vec<SmtpPeerReply>,
    pub peer_replies_omitted: Option<u64>,
}

impl SmtpDispositionFields {
    /// Keep only loggable peer fields before sharing with local loggers.
    pub fn limit(&mut self) {
        // A locally generated negative disposition is not a peer reply.
        if self.smtp_stage.is_none()
            || self.failure_kind.as_ref().map(SmtpLogLabel::as_str) != Some("smtp_reply")
        {
            self.peer_response = None;
        } else if let Some(response) = &mut self.peer_response {
            response.limit(self.smtp_stage.as_ref());
        }
        for reply in &mut self.peer_replies {
            reply.response.limit(Some(&reply.smtp_stage));
        }
    }
}

pub(crate) fn deserialize_disposition_fields<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Box<SmtpDispositionFields>>, D::Error> {
    let fields = SmtpDispositionFields::deserialize(d)?;
    Ok((fields != SmtpDispositionFields::default()).then(|| Box::new(fields)))
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpSetupPhase {
    pub phase: SmtpLogLabel,
    pub outcome: SmtpLogLabel,
    pub elapsed_ms: Option<f64>,
    pub failure_kind: Option<SmtpLogLabel>,
    pub response: Option<SmtpPeerResponse>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpSetupAttempt {
    pub mx: String,
    pub ip: Option<IpAddr>,
    pub preference: Option<u16>,
    pub outcome: SmtpLogLabel,
    pub elapsed_ms: Option<f64>,
    #[serde(default)]
    pub phases: Vec<SmtpSetupPhase>,
    pub phases_omitted: Option<u64>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpAddressList {
    pub outcome: SmtpLogLabel,
    pub address_list_build_ms: Option<f64>,
    pub mx_hosts_looked_up: Option<u64>,
    pub usable_ip_candidates: Option<u64>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpDiscovery {
    pub method: SmtpLogLabel,
    pub mta_sts: Option<SmtpLogLabel>,
    pub dane: Option<SmtpLogLabel>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConnectionPlan {
    pub session_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub result: SmtpLogLabel,
    pub route: Option<SmtpLogLabel>,
    pub egress_source: Option<String>,
    pub discovery: Option<SmtpDiscovery>,
    pub address_list: Option<SmtpAddressList>,
    pub attempts: Vec<SmtpSetupAttempt>,
    pub attempts_omitted: Option<u64>,
    pub connection_setup_ms: Option<f64>,
}

// Names come from configuration or discovery, not the classification policy.
fn limit_name(name: &mut String) {
    if name.len() > 512 || name.chars().any(char::is_control) {
        *name = "unknown".into();
    }
}

impl SmtpConnectionPlan {
    fn limit(&mut self) {
        if let Some(source) = &mut self.egress_source {
            limit_name(source);
        }
        for attempt in &mut self.attempts {
            limit_name(&mut attempt.mx);
            for phase in &mut attempt.phases {
                if phase.failure_kind.as_ref().map(SmtpLogLabel::as_str) != Some("smtp_reply") {
                    phase.response = None;
                } else if let Some(response) = &mut phase.response {
                    response.limit(Some(&phase.phase));
                }
            }
        }
    }
}

/// File record for an outbound SMTP connection plan. A plan has an event time
/// but no spool id, message creation time or envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConnectionPlanRecord {
    #[serde(rename = "type")]
    kind: PlanRecordType,
    #[serde(flatten, with = "super::ts_serializer")]
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub plan: SmtpConnectionPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PlanRecordType {
    SmtpConnectionPlan,
}

impl SmtpConnectionPlanRecord {
    pub fn new(timestamp: DateTime<Utc>, mut plan: SmtpConnectionPlan) -> Self {
        plan.limit();
        Self {
            kind: PlanRecordType::SmtpConnectionPlan,
            timestamp,
            plan,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn plan_sanitizes_names_and_withholds_auth_text() {
        let fields = json!({
            "session_id": Uuid::nil(), "result": "exhausted", "egress_source": "x".repeat(513),
            "attempts": [{"mx":"mx\nexample", "ip":"192.0.2.1", "outcome":"failed",
                "phases":[{"phase":"auth", "outcome":"error", "failure_kind":"smtp_reply",
                    "response":{"code":535, "content":"do not log"}}]}]
        });
        let record =
            SmtpConnectionPlanRecord::new(Utc::now(), serde_json::from_value(fields).unwrap());
        let value = serde_json::to_value(record).unwrap();
        let attempt = &value["attempts"][0];
        assert_eq!(value["egress_source"], "unknown");
        assert_eq!(attempt["mx"], "unknown");
        assert_eq!(attempt["phases"][0]["response"], json!({"code":535}));
    }

    #[test]
    fn transport_failure_keeps_only_independently_observed_peer_replies() {
        let mut fields: SmtpDispositionFields = serde_json::from_value(json!({
            "smtp_stage":"data_dot", "failure_kind":"response_timeout",
            "peer_response":{"code":421},
            "peer_replies":[{"smtp_stage":"rcpt_to", "response":{"code":450}}]
        }))
        .unwrap();
        fields.limit();
        assert!(fields.peer_response.is_none());
        assert_eq!(fields.peer_replies[0].response.code, 450);
    }

    #[test]
    fn bounds_approved_text_and_filters_secondary_reply_content() {
        let mut fields: SmtpDispositionFields = serde_json::from_value(json!({
            "smtp_stage":"rcpt_to", "failure_kind":"smtp_reply",
            "peer_response":{"code":450, "content":format!("{}é", "x".repeat(255))},
            "peer_replies":[
                {"smtp_stage":"auth", "response":{"code":535, "content":"secret"}},
                {"smtp_stage":"unknown_stage", "response":{"code":450, "content":"secret"}},
                {"smtp_stage":"rcpt_to", "response":{"code":450, "content":"control\ntext"}}
            ],
            "peer_replies_omitted":3
        }))
        .unwrap();
        fields.limit();
        let value = serde_json::to_value(fields).unwrap();
        assert_eq!(
            value["peer_response"]["content"].as_str().unwrap().len(),
            255
        );
        assert_eq!(value["peer_response"]["content_truncated"], true);
        let replies = value["peer_replies"].as_array().unwrap();
        assert_eq!(replies.len(), 3);
        assert_eq!(value["peer_replies_omitted"], 3);
        assert!(replies
            .iter()
            .all(|r| r["response"].get("content").is_none()));
    }
}
