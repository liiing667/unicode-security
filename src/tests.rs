// Copyright 2012-2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[test]
fn test_general_security_profile_identifier_allowed() {
    use crate::GeneralSecurityProfile;
    assert_eq!(GeneralSecurityProfile::identifier_allowed('A'), true);
    assert_eq!('A'.identifier_allowed(), true);
    assert_eq!(GeneralSecurityProfile::identifier_allowed('0'), true);
    assert_eq!('0'.identifier_allowed(), true);
    assert_eq!(GeneralSecurityProfile::identifier_allowed('_'), true);
    assert_eq!('_'.identifier_allowed(), true);
    assert_eq!(GeneralSecurityProfile::identifier_allowed('\x00'), false);
    assert_eq!('\x00'.identifier_allowed(), false);
    // U+00B5 MICRO SIGN
    assert_eq!(GeneralSecurityProfile::identifier_allowed('µ'), false);
    assert_eq!('µ'.identifier_allowed(), false);
    // U+2160 ROMAN NUMERAL ONE
    assert_eq!(GeneralSecurityProfile::identifier_allowed('Ⅰ'), false);
    assert_eq!('Ⅰ'.identifier_allowed(), false);
}

#[test]
fn test_mixed_script() {
    use crate::MixedScript;
    assert_eq!("".is_single_script(), true);
    assert_eq!("".resolve_script_set().is_empty(), false);
    assert_eq!("".resolve_script_set().is_all(), true);
    assert_eq!("A".is_single_script(), true);
    assert_eq!("A".resolve_script_set().is_empty(), false);
    assert_eq!("A".resolve_script_set().is_all(), false);
    assert_eq!("A0".is_single_script(), true);
    assert_eq!("A0".resolve_script_set().is_empty(), false);
    assert_eq!("A0".resolve_script_set().is_all(), false);
    assert_eq!("0.".is_single_script(), true);
    assert_eq!("0.".resolve_script_set().is_empty(), false);
    assert_eq!("0.".resolve_script_set().is_all(), true);
    assert_eq!("福".is_single_script(), true);
    assert_eq!("福".resolve_script_set().is_empty(), false);
    assert_eq!("福".resolve_script_set().is_all(), false);
    assert_eq!("冬の雪".is_single_script(), true);
    assert_eq!("冬の雪".resolve_script_set().is_empty(), false);
    assert_eq!("冬の雪".resolve_script_set().is_all(), false);
    assert_eq!("幻ㄒㄧㄤ".is_single_script(), true);
    assert_eq!("幻ㄒㄧㄤ".resolve_script_set().is_empty(), false);
    assert_eq!("幻ㄒㄧㄤ".resolve_script_set().is_all(), false);
    assert_eq!("日出은".is_single_script(), true);
    assert_eq!("日出은".resolve_script_set().is_empty(), false);
    assert_eq!("日出은".resolve_script_set().is_all(), false);
    assert_eq!("夏の幻ㄒㄧㄤ".is_single_script(), false);
    assert_eq!("夏の幻ㄒㄧㄤ".resolve_script_set().is_empty(), true);
    assert_eq!("夏の幻ㄒㄧㄤ".resolve_script_set().is_all(), false);
}

#[test]
fn test_confusable_detection() {
    use crate::skeleton;
    use std::string::String;
    assert_eq!(&skeleton("").collect::<String>(), "");
    assert_eq!(&skeleton("ｓ").collect::<String>(), "s");
    assert_eq!(&skeleton("ｓｓｓ").collect::<String>(), "sss");
    assert_eq!(&skeleton("ｓ؜ｓ؜ｓ").collect::<String>(), "sss");
    assert_eq!(&skeleton("ﶛ").collect::<String>(), "نمى");
    assert_eq!(&skeleton("ﶛﶛ").collect::<String>(), "نمىنمى");
}

#[test]
fn test_potential_mixed_script_detection() {
    use crate::is_potential_mixed_script_confusable_char;

    assert!(is_potential_mixed_script_confusable_char('A'));
    assert!(!is_potential_mixed_script_confusable_char('D'));
}

#[test]
fn test_augmented_script_set_fmt_debug() {
    use crate::mixed_script::AugmentedScriptSet;
    let augmented_script_sets = vec![
        AugmentedScriptSet::default(),
        AugmentedScriptSet::from('0'),
        AugmentedScriptSet::from('a'),
        AugmentedScriptSet::from('μ'),
        AugmentedScriptSet::from('汉'),
        AugmentedScriptSet::from('ひ'),
        AugmentedScriptSet::from('カ'),
        AugmentedScriptSet::from('한'),
        AugmentedScriptSet::from("汉ひ"),
        AugmentedScriptSet::from("汉a"),
        AugmentedScriptSet::from("汉μ"),
        AugmentedScriptSet::from("〆切"),
    ];
    let debug_output = vec![
        "AugmentedScriptSet {ALL}",
        "AugmentedScriptSet {ALL}",
        "AugmentedScriptSet {Latn}",
        "AugmentedScriptSet {Grek}",
        "AugmentedScriptSet {Hanb, Jpan, Kore, Hani}",
        "AugmentedScriptSet {Jpan, Hira}",
        "AugmentedScriptSet {Jpan, Kana}",
        "AugmentedScriptSet {Kore, Hang}",
        "AugmentedScriptSet {Jpan}",
        "AugmentedScriptSet {∅}",
        "AugmentedScriptSet {∅}",
        "AugmentedScriptSet {Hanb, Jpan, Kore, Hani}",
    ];

    for (ss, output) in augmented_script_sets.into_iter().zip(debug_output) {
        assert_eq!(format!("{:?}", ss), output);
    }
}

#[test]
fn test_augmented_script_set_fmt_display() {
    use crate::mixed_script::AugmentedScriptSet;
    let augmented_script_sets = vec![
        AugmentedScriptSet::default(),
        AugmentedScriptSet::from('0'),
        AugmentedScriptSet::from('a'),
        AugmentedScriptSet::from('μ'),
        AugmentedScriptSet::from('汉'),
        AugmentedScriptSet::from('ひ'),
        AugmentedScriptSet::from('カ'),
        AugmentedScriptSet::from('한'),
        AugmentedScriptSet::from("汉ひ"),
        AugmentedScriptSet::from("汉a"),
        AugmentedScriptSet::from("汉μ"),
        AugmentedScriptSet::from("〆切"),
    ];
    let debug_output = vec![
        "All",
        "All",
        "Latin",
        "Greek",
        "Han with Bopomofo, Japanese, Korean, Han",
        "Japanese, Hiragana",
        "Japanese, Katakana",
        "Korean, Hangul",
        "Japanese",
        "Empty",
        "Empty",
        "Han with Bopomofo, Japanese, Korean, Han",
    ];

    for (ss, output) in augmented_script_sets.into_iter().zip(debug_output) {
        assert_eq!(format!("{}", ss), output);
    }
}

#[test]
fn test_mixed_script_confusable_spoofing_is_flagged() {
    use crate::is_mixed_script_confusable;
    use crate::mixed_script_confusable::MixedScriptConfusableDetection;
    use crate::MixedScript;
    use unicode_script::Script;

    // "pаypаl" swaps Latin `a` for Cyrillic U+0430 while keeping the same
    // skeleton as "paypal".
    let spoof = "pаypаl";
    assert!(!spoof.is_single_script());
    assert!(is_mixed_script_confusable(spoof));

    let report = spoof.mixed_script_confusable();
    assert!(report.is_mixed_script_confusable());
    assert!(report.resolved_script_set().is_empty());
    assert!(!report.has_restricted_character());
    assert_eq!(report.restricted_characters().next(), None);
    assert_eq!(report.uncovered_characters().next(), None);

    let hits: std::vec::Vec<_> = report.confusable_chars().collect();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].char, 'а');
    assert_eq!(hits[0].index, 1);
    assert_eq!(hits[0].source_script, Script::Cyrillic);
    assert_eq!(hits[0].target_char, 'a');
    assert_eq!(hits[0].target_script, Script::Latin);
    assert_ne!(hits[0].source_script, hits[0].target_script);
    assert_eq!(hits[1].index, 5);

    // The skeleton collapses the spoof back to plain ASCII.
    let mut skeleton = report.skeleton();
    assert_eq!(skeleton.next(), Some('p'));
    assert_eq!(skeleton.collect::<std::string::String>(), "aypal");

    // A Latin/Cyrillic mixture inside "Сirсlе" (Table 1a of UTS #39) is
    // flagged, including Cyrillic es and ie.
    let circle = "Сirсlе";
    assert!(is_mixed_script_confusable(circle));
    let circle_hits: std::vec::Vec<_> = circle
        .mixed_script_confusable()
        .confusable_chars()
        .collect();
    assert!(circle_hits.iter().any(|hit| hit.char == 'С'
        && hit.source_script == Script::Cyrillic
        && hit.target_script == Script::Latin));
    assert!(circle_hits
        .iter()
        .all(|hit| hit.source_script != hit.target_script));
}

#[test]
fn test_mixed_script_confusable_legitimate_cjk_is_not_flagged() {
    use crate::is_mixed_script_confusable;
    use crate::mixed_script_confusable::MixedScriptConfusableDetection;
    use crate::MixedScript;

    // Ordinary Japanese Han/Hiragana/Katakana writing is single-script once
    // augmented with Jpan, even though the raw Script properties differ.
    for legitimate in &["冬の雪", "今日は", "カフェ", "日出은", "幻ㄒㄧㄤ"] {
        assert!(
            legitimate.is_single_script(),
            "expected single-script: {}",
            legitimate
        );
        assert!(
            !is_mixed_script_confusable(legitimate),
            "unexpected confusable verdict: {}",
            legitimate
        );
        let report = legitimate.mixed_script_confusable();
        assert!(!report.resolved_script_set().is_empty());
        // Character-level cross-script lookalikes (e.g. Katakana `カ` with
        // Han prototype `力`) can still exist; they never turn a
        // single-script string into a whole-string mixed-script confusable.
        assert!(!report.is_mixed_script_confusable());
    }

    // A genuinely mixed CJK string still must not be reported as a
    // mixed-script *confusable*; restricted Bopomofo characters make it
    // ineligible and are exposed as audit evidence.
    let mixed = "夏の幻ㄒㄧㄤ";
    assert!(!mixed.is_single_script());
    assert!(!is_mixed_script_confusable(mixed));
    let report = mixed.mixed_script_confusable();
    assert!(report.has_restricted_character());
    let restricted: std::vec::Vec<_> = report.restricted_characters().collect();
    assert_eq!(restricted, vec![(9, 'ㄒ'), (12, 'ㄧ'), (15, 'ㄤ')]);
}

#[test]
fn test_mixed_script_confusable_other_negatives() {
    use crate::is_mixed_script_confusable;
    use crate::mixed_script_confusable::MixedScriptConfusableDetection;
    use crate::MixedScript;
    use unicode_script::Script;

    // Single-script strings, including whole-script lookalikes, are not
    // *mixed-script* confusables even when their skeleton matches another
    // script.
    for single_script in &["paypal", "scope", "ѕсоре", "раураӏ", "Circ1e", ""] {
        assert!(single_script.is_single_script());
        assert!(!is_mixed_script_confusable(single_script));
        assert!(!single_script
            .mixed_script_confusable()
            .resolved_script_set()
            .is_empty());
    }

    // A mixed-script string containing a character without a cross-script
    // prototype cannot be fully substituted and is therefore not confusable.
    let uncovered = "ЁA";
    assert!(!uncovered.is_single_script());
    assert!(!is_mixed_script_confusable(uncovered));
    let report = uncovered.mixed_script_confusable();
    assert!(!report.has_restricted_character());
    assert_eq!(
        report.uncovered_characters().collect::<std::vec::Vec<_>>(),
        vec![(0, 'Ё', Script::Cyrillic)]
    );

    // Restricted characters (here U+00B5 MICRO SIGN) disqualify the string
    // from identifier-based detection regardless of the skeleton.
    let restricted = "µа";
    assert!(!is_mixed_script_confusable(restricted));
    let report = restricted.mixed_script_confusable();
    assert!(report.has_restricted_character());
    assert_eq!(
        report.restricted_characters().collect::<std::vec::Vec<_>>(),
        vec![(0, 'µ')]
    );
}

#[test]
fn test_mixed_script_confusable_common_and_inherited_are_ignored() {
    use crate::is_mixed_script_confusable;
    use crate::mixed_script_confusable::MixedScriptConfusableDetection;

    // Digits and punctuation are Common characters without a script of their
    // own; a single-script Latin label containing them stays clean.
    let label = "Abc123.";
    assert!(!is_mixed_script_confusable(label));
    let report = label.mixed_script_confusable();
    assert!(!report.resolved_script_set().is_empty());
    assert_eq!(report.confusable_chars().next(), None);
    assert_eq!(report.uncovered_characters().next(), None);
}
