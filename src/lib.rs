//! Some items for implementing [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/) headers with [axum](https://crates.io/crates/axum)
#![deny(unsafe_code)]

use axum::http::HeaderValue;
use regex::RegexSet;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, Ord, PartialOrd)]
pub enum CspDirectiveType {
    BaseUri,
    ChildSrc,
    ConnectSrc,
    DefaultSrc,
    // Experimental!
    FencedFrameSrc,
    FontSrc,
    FormAction,
    FrameAncestors,
    FrameSrc,
    ImgSrc,
    ManifestSrc,
    MediaSrc,
    // Experimental!
    NavigateTo,
    ObjectSrc,
    PrefetchSrc,
    // Experimental/Deprecated, you should use this AND report-uri
    ReportTo,
    // Experimental/Deprecated, you should use this AND report-to
    ReportUri,
    // Experimental!
    RequireTrustedTypesFor,
    Sandbox,
    ScriptSource,
    ScriptSourceAttr,
    ScriptSourceElem,
    StyleSource,
    StyleSourceAttr,
    StyleSourceElem,
    // Experimental!
    TrustedTypes,
    UpgradeInsecureRequests,
    WorkerSource,
}

impl AsRef<str> for CspDirectiveType {
    fn as_ref(&self) -> &str {
        match self {
            Self::BaseUri => "base-uri",
            Self::ChildSrc => "child-src",
            Self::ConnectSrc => "connect-src",
            Self::DefaultSrc => "default-src",
            // Experimental!
            Self::FencedFrameSrc => "fenced-frame-src",
            Self::FontSrc => "font-src",
            Self::FormAction => "form-action",
            Self::FrameAncestors => "frame-ancestors",
            Self::FrameSrc => "frame-src",
            Self::ImgSrc => "img-src",
            Self::ManifestSrc => "manifest-src",
            Self::MediaSrc => "media-src",
            // Experimental!
            Self::NavigateTo => "navigate-to",
            Self::ObjectSrc => "object-src",
            Self::PrefetchSrc => "prefetch-src",
            // Experimental/Deprecated, you should use this AND report-uri
            Self::ReportTo => "report-to",
            // Experimental/Deprecated, you should use this AND report-to
            Self::ReportUri => "report-uri",
            // Experimental!
            Self::RequireTrustedTypesFor => "require-trusted-types-for",
            Self::Sandbox => "sandbox",
            Self::ScriptSourceAttr => "script-src-attr",
            Self::ScriptSourceElem => "script-src-elem",
            Self::ScriptSource => "script-src",
            Self::StyleSourceAttr => "style-src-attr",
            Self::StyleSourceElem => "style-src-elem",
            Self::StyleSource => "style-src",
            // Experimental!
            Self::TrustedTypes => "trusted-types",
            Self::UpgradeInsecureRequests => "upgrade-insecure-requests",
            Self::WorkerSource => "worker-src",
        }
    }
}

impl Display for CspDirectiveType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl From<CspDirectiveType> for String {
    fn from(input: CspDirectiveType) -> String {
        input.as_ref().to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CspDirective {
    pub directive_type: CspDirectiveType,
    pub values: Vec<CspValue>,
}

impl CspDirective {
    #[must_use]
    pub fn from(directive_type: CspDirectiveType, values: Vec<CspValue>) -> Self {
        Self {
            directive_type,
            values,
        }
    }

    /// Build a default-src 'self' directive
    pub fn default_self() -> Self {
        Self {
            directive_type: CspDirectiveType::DefaultSrc,
            values: vec![CspValue::SelfSite],
        }
    }
}

impl Display for CspDirective {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let space = if self.values.is_empty() { "" } else { " " };
        f.write_fmt(format_args!(
            "{}{}{}",
            self.directive_type.as_ref(),
            space,
            self.values
                .iter()
                .map(|v| String::from(v.to_owned()))
                .collect::<Vec<String>>()
                .join(" ")
        ))
    }
}

impl From<CspDirective> for HeaderValue {
    fn from(input: CspDirective) -> HeaderValue {
        match HeaderValue::from_str(&input.to_string()) {
            Ok(val) => val,
            Err(e) => panic!("Failed to build HeaderValue from CspDirective: {}", e),
        }
    }
}

/// Build these to find urls to add headers to
#[derive(Clone, Debug)]
pub struct CspUrlMatcher {
    pub matcher: RegexSet,
    pub directives: Vec<CspDirective>,
}

impl CspUrlMatcher {
    #[must_use]
    pub fn new(matcher: RegexSet) -> Self {
        Self {
            matcher,
            directives: vec![],
        }
    }
    pub fn with_directive(&mut self, directive: CspDirective) -> &mut Self {
        self.directives.push(directive);
        self
    }

    /// Exposes the internal matcher.is_match as a struct method
    pub fn is_match(&self, text: &str) -> bool {
        self.matcher.is_match(text)
    }

    /// build a matcher which will emit `default-src 'self';` for all matches
    pub fn default_all_self() -> Self {
        Self {
            matcher: RegexSet::new([r#".*"#]).unwrap(),
            directives: vec![CspDirective {
                directive_type: CspDirectiveType::DefaultSrc,
                values: vec![CspValue::SelfSite],
            }],
        }
    }

    /// build a matcher which will emit `default-src 'self';` for given matches
    pub fn default_self(matcher: RegexSet) -> Self {
        Self {
            matcher,
            directives: vec![CspDirective {
                directive_type: CspDirectiveType::DefaultSrc,
                values: vec![CspValue::SelfSite],
            }],
        }
    }
}

/// Returns the statement as it should show up in the headers
impl From<CspUrlMatcher> for HeaderValue {
    fn from(input: CspUrlMatcher) -> HeaderValue {
        let mut res = String::new();
        for directive in input.directives {
            res.push_str(directive.directive_type.as_ref());
            for val in directive.values {
                res.push_str(&format!(" {}", String::from(val)));
            }
            res.push_str("; ");
        }
        HeaderValue::from_str(res.trim()).unwrap()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
/// Enum for [CSP source values](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/Sources#sources)
pub enum CspValue {
    None,
    /// Equivalent to 'self' but can't just `Self` in rust
    SelfSite,
    StrictDynamic,
    ReportSample,

    UnsafeInline,
    UnsafeEval,
    UnsafeHashes,
    /// Experimental!
    UnsafeAllowRedirects,
    Host {
        value: String,
    },
    SchemeHttps,
    SchemeHttp,
    SchemeData,
    SchemeOther {
        value: String,
    },
    Nonce {
        value: String,
    },
    Sha256 {
        value: String,
    },
    Sha384 {
        value: String,
    },
    Sha512 {
        value: String,
    },
}

impl From<CspValue> for String {
    fn from(input: CspValue) -> String {
        match input {
            CspValue::None => "'none'".to_string(),
            CspValue::SelfSite => "'self'".to_string(),
            CspValue::StrictDynamic => "'strict-dynamic'".to_string(),
            CspValue::ReportSample => "'report-sample'".to_string(),
            CspValue::UnsafeInline => "'unsafe-inline'".to_string(),
            CspValue::UnsafeEval => "'unsafe-eval'".to_string(),
            CspValue::UnsafeHashes => "'unsafe-hashes'".to_string(),
            CspValue::UnsafeAllowRedirects => "'unsafe-allow-redirects'".to_string(),
            CspValue::SchemeHttps => "https:".to_string(),
            CspValue::SchemeHttp => "http:".to_string(),
            CspValue::SchemeData => "data:".to_string(),
            CspValue::Host { value } | CspValue::SchemeOther { value } => value.to_string(),
            CspValue::Nonce { value } => format!("nonce-{value}"),
            CspValue::Sha256 { value } => format!("sha256-{value}"),
            CspValue::Sha384 { value } => format!("sha384-{value}"),
            CspValue::Sha512 { value } => format!("sha512-{value}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
/// Builder that ends up in a HeaderValue
pub struct CspHeaderBuilder {
    pub directive_map: HashMap<CspDirectiveType, Vec<CspValue>>,
}

impl CspHeaderBuilder {
    pub fn new() -> Self {
        Self {
            directive_map: HashMap::new(),
        }
    }

    pub fn add(mut self, directive: CspDirectiveType, values: Vec<CspValue>) -> Self {
        self.directive_map.entry(directive).or_default();

        values.into_iter().for_each(|val| {
            if !self.directive_map.get(&directive).unwrap().contains(&val) {
                self.directive_map.get_mut(&directive).unwrap().push(val);
            }
        });
        self
    }

    pub fn finish(self) -> HeaderValue {
        let mut keys = self
            .directive_map
            .keys()
            .collect::<Vec<&CspDirectiveType>>();
        keys.sort();

        let directive_strings: Vec<String> = keys
            .iter()
            .map(|directive| {
                let mut directive_string = String::new();
                directive_string.push_str(&format!(" {}", directive));
                let mut values = match self.directive_map.get(directive) {
                    Some(val) => val.to_owned(),
                    None => vec![],
                };
                values.sort();
                values.into_iter().for_each(|val| {
                    directive_string.push_str(&format!(" {}", String::from(val)));
                });
                directive_string.trim().to_string()
            })
            .collect();

        HeaderValue::from_str(&directive_strings.join("; "))
            .expect("Failed to build header value from directive strings")
    }
}
