use axum_csp::{CspDirectiveType, CspHeaderBuilder, CspValue};

#[test]
pub fn test_csp_set_ordering() {
    let builder = CspHeaderBuilder::new()
        .add(
            CspDirectiveType::ScriptSource,
            // this tests that the ordering is stable
            vec![CspValue::UnsafeInline, CspValue::SelfSite],
        )
        .add(CspDirectiveType::DefaultSrc, vec![CspValue::SelfSite]);
    let res = builder.finish();
    assert_eq!(
        res,
        "default-src 'self'; script-src 'self' 'unsafe-inline'".to_string()
    );
}
