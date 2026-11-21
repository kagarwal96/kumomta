use super::*;
use serde_json::{json, Value as JsonValue};

fn policy(params: JsonValue) -> anyhow::Result<Policy> {
    Policy::try_from(serde_json::from_value::<Params>(params)?)
}

#[test]
fn matches_mx_hosts_on_dns_label_boundaries() {
    let p = policy(json!({"providers": {
        "base": ["Example.COM."], "gateway": ["*.mx.example.com"],
        "explicit": ["=relay.mx.example.com"]
    }}))
    .unwrap();
    for (host, expected) in [
        ("EXAMPLE.com.", "base"),
        ("mx.example.com", "base"),
        ("Mx2.MX.Example.COM.:2525", "gateway"),
        ("relay.mx.example.com", "explicit"),
        ("x.relay.mx.example.com", "gateway"),
        ("notexample.com", "other"),
        ("example.com.attacker.test", "other"),
        ("mx.example.com:70000", "other"),
        ("192.0.2.42", "other"),
        ("[::1]:25", "other"),
        (".", "unknown"),
    ] {
        assert_eq!(p.provider(host), expected, "{host}");
    }
    assert_eq!(p.plan_provider([].into_iter()), "unknown");
    assert_eq!(
        p.plan_provider(["a.example.com", "b.example.com"].into_iter()),
        "base"
    );
    assert_eq!(
        p.plan_provider(["a.mx.example.com", "b.example.com"].into_iter()),
        "other"
    );
    assert_eq!(p.plan_provider(["a.test", "b.test"].into_iter()), "other");
    assert_eq!(p.bounded_group("gateway"), "gateway");
    assert_eq!(p.bounded_group("unknown"), "unknown");
    assert_eq!(p.bounded_group("mx.example.com"), "other");
}

#[test]
fn rejects_ambiguous_rules_and_unbounded_labels() {
    for invalid in [
        json!({"providers": {"example.org": ["example.org"]}}),
        json!({"providers": {"unknown": ["example.org"]}}),
        json!({"providers": {"a": ["example.org"], "b": ["*.EXAMPLE.org."]}}),
        json!({"providers": {"a": ["127.0.0.1"]}}),
        json!({"providers": {"a": ["email@example.org"]}}),
        json!({"providers": {"a": vec!["example.org"; MAX_HOST_RULES + 1]}}),
        json!({"providers": (0..=MAX_PROVIDERS).map(|i| (format!("group{i}"), vec![format!("mx{i}.example")])).collect::<BTreeMap<_, _>>() }),
        json!({"reasons": ["bad label"]}),
        json!({"reasons": ["a".repeat(49)]}),
        json!({"reasons": vec!["reason"; MAX_REASONS + 1]}),
        json!({"enhanced_codes": vec!["4.7.1"; MAX_ENHANCED_CODES + 1]}),
        json!({"enhanced_codes": ["4.7.1000"]}),
        json!({"enhanced_codes": ["4.7.+1"]}),
        json!({"enhanced_codes": ["5.007.1"]}),
        json!({"enhanced_codes": ["2.0.0"]}),
    ] {
        assert!(policy(invalid.clone()).is_err(), "{invalid}");
    }
}

#[test]
fn distinguishes_unlisted_from_unusable_dsns() {
    let p = policy(json!({"enhanced_codes": ["4.7.1"]})).unwrap();
    for (code, message, expected) in [
        (451, "4.7.1 listed", "4.7.1"),
        (599, "5.8.2 unlisted", "other"),
        (400, "no enhanced code", "unknown"),
        (550, "4.7.1 mismatched class", "unknown"),
        (451, "4.1000.1 invalid subject", "unknown"),
        (451, "4.7.1000 invalid detail", "unknown"),
    ] {
        assert_eq!(
            p.dsn(&Response::with_code_and_message(code, message)),
            expected,
            "{message}"
        );
    }
}

#[test]
fn classifier_receives_no_command_or_sensitive_or_partial_text() {
    let mut response = Response {
        command: Some("RCPT TO:<private@example.invalid>".into()),
        ..Response::with_code_and_message(451, "4.7.1 retry later")
    };
    let (stage, input, truncated) = classifier_input("rcpt_to", &response);
    assert_eq!(stage, "rcpt_to");
    assert!(!truncated);
    assert_eq!(
        serde_json::to_value(input).unwrap(),
        json!({
            "code":451, "enhanced_code":{"class":4,"subject":7,"detail":1}, "content":"retry later"
        })
    );
    for (stage, expected) in [
        ("auth", "auth"),
        ("data_write", "data_write"),
        ("pipeline", "pipeline"),
        ("private arguments", "other"),
    ] {
        let (stage, input, _) = classifier_input(stage, &response);
        assert_eq!(stage, expected);
        assert!(input.content.is_none());
    }
    response.content = "x".repeat(MAX_CLASSIFIER_INPUT + 1);
    let (_, input, truncated) = classifier_input("data_dot", &response);
    assert!(truncated && input.content.is_none());
}

#[test]
fn classifier_output_is_typed_and_bounded() -> anyhow::Result<()> {
    let lua = Lua::new();
    let classify = |chunk: &str| lua.load(chunk).eval::<Classification>();
    let result = classify("return {reason='limited', content=string.rep('x', 255) .. 'é'}")?;
    assert_eq!(result.reason.as_deref(), Some("limited"));
    assert_eq!(result.content, Some("x".repeat(255)));
    assert!(result.truncated);
    let result = classify(r"return {reason=string.rep('x', 49), content='line\nfeed'}")?;
    assert!(result.reason.is_none() && result.content.is_none());
    for invalid in [
        "return 'peer text'",
        "return {reason={}}",
        "return {content={}}",
    ] {
        assert!(classify(invalid).is_err(), "{invalid}");
    }
    Ok(())
}
