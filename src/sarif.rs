//! SARIF 2.1.0 export (`RUDRA_REPORT_FORMAT=sarif`).
//!
//! When set, the report file written to `RUDRA_REPORT_PATH` is a complete
//! SARIF 2.1.0 log instead of the native TOML report list. The mapping is
//! the one used by the external adapter in the lockbud-stable workspace:
//! ruleId from the analyzer's base name (`SendSyncVariance:/Phantom...` ->
//! `rudra/SendSyncVariance`), the full analyzer path in result properties,
//! ReportLevel::Error/Warning/Info -> error/warning/note, and Rudra's
//! end-exclusive `line:col: line:col` spans converted to SARIF's inclusive
//! `endColumn`. The colored `source` snippet is kept verbatim in result
//! properties.

use serde_json::{json, Value};

use crate::report::Report;

const SARIF_SCHEMA: &str = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// A parsed Rudra span. `end_col_excl` is ONE PAST the last column (rustc
/// convention); conversion to SARIF's inclusive endColumn happens in
/// [`sarif_region`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Span {
    path: String,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col_excl: u32,
}

/// Parse `src/main.rs:9:1: 9:37`; the ` (#N)` macro-context suffix is
/// optional, and a single `path:line:col` position yields an open region.
fn parse_span(text: &str) -> Option<Span> {
    let core = match text.trim().split_once(" (#") {
        Some((core, _)) => core,
        None => text.trim(),
    };
    let (head, tail) = core.split_once(": ")?;
    let (path, sl, sc) = split_path_line_col(head)?;
    let (el, ec) = match tail.split_once(':') {
        Some((el_str, ec_str)) => {
            (el_str.parse::<u32>().ok()?, ec_str.parse::<u32>().ok()?)
        }
        None => (sl, sc), // tolerate single-position spans
    };
    Some(Span {
        path: path.to_owned(),
        start_line: sl,
        start_col: sc,
        end_line: el,
        end_col_excl: ec,
    })
}

/// Parse `path:line:col` from the right: two numeric segments plus a
/// non-empty path prefix (paths may themselves contain colons).
fn split_path_line_col(s: &str) -> Option<(&str, u32, u32)> {
    let mut parts = s.rsplitn(3, ':');
    let col = parts.next()?.parse::<u32>().ok()?;
    let line = parts.next()?.parse::<u32>().ok()?;
    let path = parts.next()?;
    if path.is_empty() {
        return None;
    }
    Some((path, line, col))
}

fn sarif_region(span: &Span) -> Value {
    let mut region = json!({ "startLine": span.start_line });
    region["startColumn"] = json!(span.start_col);
    if span.end_line != span.start_line {
        region["endLine"] = json!(span.end_line);
    }
    // Rudra end columns are end-exclusive; SARIF endColumn is inclusive.
    region["endColumn"] = json!(span.end_col_excl.saturating_sub(1).max(span.start_col));
    region
}

fn sarif_location(span: &Span) -> Value {
    json!({ "physicalLocation": {
        "artifactLocation": { "uri": span.path },
        "region": sarif_region(span),
    }})
}

/// `SendSyncVariance:/PhantomSendForSend/...` -> `SendSyncVariance`
fn analyzer_base(analyzer: &str) -> &str {
    match analyzer.find(':') {
        Some(idx) => &analyzer[..idx],
        None => analyzer,
    }
}

fn level_text(level: crate::report::ReportLevel) -> &'static str {
    match level {
        crate::report::ReportLevel::Error => "error",
        crate::report::ReportLevel::Warning => "warning",
        crate::report::ReportLevel::Info => "note",
    }
}

fn cwe_for(analyzer_base: &str) -> &'static str {
    match analyzer_base {
        "UnsafeDataflow" => "CWE-416",
        "SendSyncVariance" => "CWE-362",
        _ => "",
    }
}

fn short_description(analyzer_base: &str) -> String {
    match analyzer_base {
        "UnsafeDataflow" => {
            "Weak lifetime bypass: unsafe operation reads or writes a value \
             whose lifetime was bypassed"
                .to_owned()
        }
        "SendSyncVariance" => {
            "Unsound unsafe impl of Send/Sync".to_owned()
        }
        "UnsafeDestructor" => {
            "Drop implementation contains user-written unsafe operations"
                .to_owned()
        }
        other => format!("rudra {} finding", other),
    }
}

/// Build one complete SARIF 2.1.0 log from the collected reports. Returns
/// `None` when there are no reports (mirroring the TOML logger, which
/// writes no file for an empty set).
pub(crate) fn reports_to_sarif(reports: &[Report]) -> Option<Value> {
    if reports.is_empty() {
        return None;
    }

    let mut rules: Vec<Value> = Vec::new();
    let mut seen_rules: Vec<String> = Vec::new();
    let mut artifacts: Vec<Value> = Vec::new();
    let mut seen_uris: Vec<String> = Vec::new();
    let mut results: Vec<Value> = Vec::new();

    for report in reports {
        let base = analyzer_base(&report.analyzer).to_owned();
        let rule_id = format!("rudra/{}", base);
        if !seen_rules.iter().any(|id| id == &rule_id) {
            seen_rules.push(rule_id.clone());
            let mut rule = json!({
                "id": rule_id,
                "name": base,
                "shortDescription": { "text": short_description(&base) },
                "fullDescription": { "text": short_description(&base) },
            });
            let cwe = cwe_for(&base);
            if !cwe.is_empty() {
                rule["properties"] = json!({ "cwe": [cwe] });
            }
            rules.push(rule);
        }

        let mut result = json!({
            "ruleId": rule_id,
            "level": level_text(report.level),
            "message": { "text": report.description },
            "properties": {
                "detector": "rudra",
                "analyzer": report.analyzer,
                "source": report.source,
            },
        });
        match parse_span(&report.location) {
            Some(span) => {
                result["locations"] = json!([sarif_location(&span)]);
                if !seen_uris.iter().any(|u| u == &span.path) {
                    seen_uris.push(span.path.clone());
                    artifacts.push(json!({ "location": { "uri": span.path } }));
                }
            }
            None => {
                // Unparseable location: keep the finding, mark the span.
                result["locations"] = json!([{ "physicalLocation": {
                    "artifactLocation": { "uri": "<unknown>" },
                    "region": { "startLine": 1 },
                }}]);
                result["properties"]["location"] = json!(report.location);
            }
        }
        results.push(result);
    }

    Some(json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "rudra",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/sslab-gatech/Rudra",
                "rules": rules,
            }},
            "results": results,
            "artifacts": artifacts,
            "invocations": [{ "executionSuccessful": true }],
            "properties": {
                "columnConvention": "1-based lines/columns; Rudra spans are end-exclusive and are exported as SARIF's inclusive endColumn",
            },
        }],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Report, ReportLevel};
    use std::borrow::Cow;

    fn report(level: ReportLevel, analyzer: &str, location: &str) -> Report {
        Report {
            level,
            analyzer: Cow::Owned(analyzer.to_owned()),
            description: Cow::Owned("description".to_owned()),
            location: location.to_owned(),
            source: "unsafe impl<P: Ord> Send for Atom<P>".to_owned(),
        }
    }

    #[test]
    fn test_parse_span() {
        let span = parse_span("tests/send_sync/wild_send.rs:9:1: 9:37").unwrap();
        assert_eq!(span.path, "tests/send_sync/wild_send.rs");
        assert_eq!(span.start_line, 9);
        assert_eq!(span.start_col, 1);
        assert_eq!(span.end_line, 9);
        assert_eq!(span.end_col_excl, 37);
    }

    #[test]
    fn test_parse_span_with_context_suffix() {
        let span = parse_span("src/main.rs:5:3: 5:10 (#0)").unwrap();
        assert_eq!(span.end_col_excl, 10);
    }

    #[test]
    fn test_sarif_envelope_and_levels() {
        let reports = vec![
            report(
                ReportLevel::Error,
                "SendSyncVariance:/PhantomSendForSend/NaiveSendForSend/RelaxSend",
                "cases/send-sync-wild-send/src/lib.rs:9:1: 9:37",
            ),
            report(
                ReportLevel::Warning,
                "UnsafeDataflow:/ReadFlow",
                "cases/panic-safety-order-unsafe/src/lib.rs:10:1: 15:2",
            ),
        ];
        let sarif = reports_to_sarif(&reports).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "rudra");
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(
            run["tool"]["driver"]["rules"][0]["properties"]["cwe"][0],
            "CWE-362"
        );
        assert_eq!(run["tool"]["driver"]["rules"][1]["properties"]["cwe"][0], "CWE-416");
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "rudra/SendSyncVariance");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["properties"]["analyzer"],
            "SendSyncVariance:/PhantomSendForSend/NaiveSendForSend/RelaxSend"
        );
        assert_eq!(results[1]["level"], "warning");
        // end-exclusive 9:37 -> inclusive endColumn 36
        let region = &results[0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 9);
        assert_eq!(region["startColumn"], 1);
        assert_eq!(region["endColumn"], 36);
        // artifacts deduped and registered
        assert_eq!(run["artifacts"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_empty_reports_write_nothing() {
        assert!(reports_to_sarif(&[]).is_none());
    }

    #[test]
    fn test_unparseable_location_keeps_finding() {
        let reports = vec![report(
            ReportLevel::Warning,
            "UnsafeDestructor",
            "no real span here",
        )];
        let sarif = reports_to_sarif(&reports).unwrap();
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "rudra/UnsafeDestructor");
        assert_eq!(result["level"], "warning");
        assert_eq!(
            result["properties"]["location"].as_str().unwrap(),
            "no real span here"
        );
        // no CWE tag for this analyzer
        assert!(sarif["runs"][0]["tool"]["driver"]["rules"][0]
            .get("properties")
            .is_none());
    }
}
