use axum::http::HeaderValue;
use axum_csp::{CspDirective, CspDirectiveType, CspHeaderBuilder, CspUrlMatcher, CspValue};
use regex::RegexSet;

#[test]
fn test_cspdirectivetype_string() {
    let directive = CspDirectiveType::ImgSrc;
    assert_eq!(directive.to_string(), "img-src");
}

#[test]
fn test_example() {
    let csp_matchers = vec![
        CspUrlMatcher {
            matcher: RegexSet::new([r#"/hello"#]).expect("Failed to build a regex"),
            directives: vec![],
        }
        .with_directive(CspDirective::from(
            CspDirectiveType::DefaultSrc,
            vec![CspValue::SelfSite],
        ))
        .to_owned(),
        CspUrlMatcher::new(RegexSet::new([r#"/hello"#]).expect("Failed to build a regex")),
        CspUrlMatcher::default_self(RegexSet::new([r#"/hello"#]).expect("Failed to build a regex")),
        CspUrlMatcher::default_all_self(),
    ];

    assert!(!csp_matchers.is_empty());
    for matcher in csp_matchers {
        assert!(matcher.matcher.is_match("/hello"));
        assert!(matcher.is_match("/hello"));

        let _header: HeaderValue = matcher.into();
    }
}

#[test]
fn test_directive_to_string() {
    let directive: CspDirective = CspDirective {
        directive_type: CspDirectiveType::ImgSrc,
        values: vec![CspValue::SelfSite, CspValue::SchemeHttps],
    };

    let res = directive.to_string();
    assert_eq!(res, "img-src 'self' https:".to_string());

    let header: HeaderValue = directive.into();
    assert!(header == "img-src 'self' https:".to_string());
}

#[test]
fn test_directives_to_string() {
    let cspset = CspHeaderBuilder::new()
        .add(CspDirectiveType::ImgSrc, vec![CspValue::SelfSite])
        .add(CspDirectiveType::DefaultSrc, vec![CspValue::SchemeHttps])
        .finish();

    let expected = HeaderValue::from_static("default-src https:; img-src 'self'");
    assert_eq!(cspset, expected);
}
