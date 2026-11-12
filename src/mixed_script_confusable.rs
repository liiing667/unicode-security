//! Whole-string [mixed-script confusable](https://www.unicode.org/reports/tr39/#Mixed_Script_Confusables)
//! detection.
//!
//! The character-level helpers in [`crate::mixed_script`] and
//! [`crate::confusable_detection`] only answer narrow questions:
//!
//! * [`crate::MixedScript::is_single_script`] reports whether a string is
//!   mixed-script at all, which also happens for perfectly legitimate text
//!   such as Japanese Han/Kana mixtures once the [resolved script set] is
//!   empty.
//! * [`crate::is_potential_mixed_script_confusable_char`] reports whether a
//!   single character has a confusable prototype in another script, without
//!   knowing anything about the surrounding string.
//!
//! This module combines the three ingredients required by
//! [UTS #39](https://www.unicode.org/reports/tr39/) sections 4 and 5.1 to
//! decide whether a *whole identifier* is a mixed-script confusable:
//!
//! 1. the [General Security Profile], so restricted characters make the
//!    identifier ineligible for the identifier-based detection;
//! 2. the [resolved script set], so ordinary CJK mixed writing (for example
//!    Han together with Hiragana or Katakana) is treated as single-script and
//!    therefore never flagged;
//! 3. the [skeleton] machinery, so the audit evidence can show which script
//!    each suspicious character is confusable towards.
//!
//! The entry point is [`MixedScriptConfusableDetection::mixed_script_confusable`].
//!
//! [resolved script set]: https://www.unicode.org/reports/tr39/#def-resolved-script-set
//! [General Security Profile]: https://www.unicode.org/reports/tr39/#General_Security_Profile
//! [skeleton]: crate::skeleton

use crate::confusable_detection::skeleton;
use crate::general_security_profile::GeneralSecurityProfile;
use crate::mixed_script::AugmentedScriptSet;
use crate::tables::confusable_detection::char_confusable_prototype;
use crate::tables::potential_mixed_script_confusable::potential_mixed_script_confusable;
use core::str::Chars;
use unicode_script::Script;

/// Scripts treated as ignored by UTS #39 mixed-script detection.
///
/// Characters whose [script property](unicode_script::Script) is
/// [`Script::Common`] (`Zyyy`) or [`Script::Inherited`] (`Zinh`) do not
/// contribute a script of their own: per UTS #39 they "are ignored when
/// testing for differences in script". [`Script::Unknown`] (`Zzzz`) is treated
/// the same way, matching the generator rules behind
/// [`crate::is_potential_mixed_script_confusable_char`].
fn is_ignored_script(script: Script) -> bool {
    matches!(script, Script::Common | Script::Inherited | Script::Unknown)
}

/// The script a character belongs to, for mixed-script purposes.
fn source_script(c: char) -> Script {
    Script::from(c)
}

/// Iterate over the non-ignored scripts reached by the confusable prototype
/// of a character.
///
/// Characters without an explicit entry in the confusable data are their own
/// prototype, in which case the character itself is yielded once.
fn target_scripts(c: char) -> TargetScripts {
    match char_confusable_prototype(c) {
        Some(prototype) => TargetScripts::Prototype(prototype, 0),
        None => TargetScripts::Self_(c),
    }
}

enum TargetScripts {
    Prototype(&'static [char], usize),
    Self_(char),
}

impl Iterator for TargetScripts {
    type Item = (char, Script);

    fn next(&mut self) -> Option<(char, Script)> {
        match self {
            TargetScripts::Prototype(prototype, index) => {
                while let Some(&prototype_char) = prototype.get(*index) {
                    *index += 1;
                    let script = source_script(prototype_char);
                    if !is_ignored_script(script) {
                        return Some((prototype_char, script));
                    }
                }
                None
            }
            TargetScripts::Self_(c) => {
                let c = *c;
                *self = TargetScripts::Prototype(&[], 0);
                let script = source_script(c);
                if is_ignored_script(script) {
                    None
                } else {
                    Some((c, script))
                }
            }
        }
    }
}

/// Audit evidence for a single character participating in a mixed-script
/// confusable.
///
/// Each record connects the offending character with the script it
/// contributes to the identifier and the non-ignored script of its
/// [`skeleton`] prototype, which is the evidence that the
/// character can stand in for a different script.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConfusableChar {
    /// The character as it appears in the input identifier.
    pub char: char,
    /// Byte offset of [`ConfusableChar::char`] inside the input string.
    pub index: usize,
    /// Script of the input character, never [`Script::Common`],
    /// [`Script::Inherited`] or [`Script::Unknown`].
    pub source_script: Script,
    /// The first non-ignored character of the confusable prototype.
    ///
    /// This is the same substitution used while computing
    /// [`skeleton`]. When the character has no explicit
    /// prototype it is the character itself.
    pub target_char: char,
    /// Script of [`ConfusableChar::target_char`], guaranteed to differ from
    /// [`ConfusableChar::source_script`] and to be a non-ignored script.
    pub target_script: Script,
}

/// Iterator yielding the [confusable characters](ConfusableChar) of a string.
#[derive(Clone, Debug)]
pub struct ConfusableCharIter<'a> {
    chars: Chars<'a>,
    index: usize,
}

impl Iterator for ConfusableCharIter<'_> {
    type Item = ConfusableChar;

    fn next(&mut self) -> Option<ConfusableChar> {
        for c in self.chars.by_ref() {
            let index = self.index;
            self.index += c.len_utf8();
            let source = source_script(c);
            if is_ignored_script(source) {
                continue;
            }
            if !potential_mixed_script_confusable(c) {
                continue;
            }
            if let Some((target_char, target_script)) =
                target_scripts(c).find(|&(_, script)| script != source)
            {
                return Some(ConfusableChar {
                    char: c,
                    index,
                    source_script: source,
                    target_char,
                    target_script,
                });
            }
        }
        None
    }
}

/// Iterator yielding characters rejected by the
/// [General Security Profile](https://www.unicode.org/reports/tr39/#General_Security_Profile).
#[derive(Clone, Debug)]
pub struct RestrictedCharIter<'a> {
    chars: Chars<'a>,
    index: usize,
}

impl Iterator for RestrictedCharIter<'_> {
    type Item = (usize, char);

    fn next(&mut self) -> Option<(usize, char)> {
        for c in self.chars.by_ref() {
            let index = self.index;
            self.index += c.len_utf8();
            if !c.identifier_allowed() {
                return Some((index, c));
            }
        }
        None
    }
}

/// Iterator yielding non-ignored characters that are not potential
/// mixed-script confusables.
///
/// Such characters keep their own script in the
/// [`skeleton`], so a mixed-script identifier containing one
/// cannot have its scripts fully substituted and therefore is not a
/// mixed-script confusable.
#[derive(Clone, Debug)]
pub struct UncoveredCharIter<'a> {
    chars: Chars<'a>,
    index: usize,
}

impl Iterator for UncoveredCharIter<'_> {
    type Item = (usize, char, Script);

    fn next(&mut self) -> Option<(usize, char, Script)> {
        for c in self.chars.by_ref() {
            let index = self.index;
            self.index += c.len_utf8();
            let script = source_script(c);
            if is_ignored_script(script) || potential_mixed_script_confusable(c) {
                continue;
            }
            return Some((index, c, script));
        }
        None
    }
}

/// Auditable result of the whole-string mixed-script confusable check.
///
/// Construct one with
/// [`MixedScriptConfusableDetection::mixed_script_confusable`]. The boolean
/// verdict is available through
/// [`MixedScriptConfusableReport::is_mixed_script_confusable`], while the
/// iterators expose every piece of evidence used while reaching it.
///
/// The report borrows the input string and performs no allocation, so it is
/// usable in `no_std` environments.
#[derive(Clone, Debug)]
pub struct MixedScriptConfusableReport<'a> {
    string: &'a str,
    resolved_script_set: AugmentedScriptSet,
    has_restricted_char: bool,
}

impl<'a> MixedScriptConfusableReport<'a> {
    fn scan(string: &'a str) -> Self {
        let mut resolved_script_set = AugmentedScriptSet::default();
        let mut has_restricted_char = false;
        for c in string.chars() {
            if !c.identifier_allowed() {
                has_restricted_char = true;
            }
            resolved_script_set.intersect_with(c.into());
        }
        Self {
            string,
            resolved_script_set,
            has_restricted_char,
        }
    }

    /// Whether the string is a mixed-script confusable according to
    /// UTS #39.
    ///
    /// This returns `true` exactly when all of the following hold:
    ///
    /// * every character is
    ///   [allowed for identifiers](GeneralSecurityProfile::identifier_allowed)
    ///   under the General Security Profile;
    /// * the string is mixed-script, meaning its
    ///   [resolved script set](AugmentedScriptSet) is empty, so legitimate
    ///   single-script CJK writing such as Han mixed with Hiragana or
    ///   Katakana is not flagged;
    /// * every non-ignored character is a
    ///   [potential mixed-script confusable](crate::is_potential_mixed_script_confusable_char),
    ///   i.e. it has a confusable prototype in another non-ignored script.
    ///
    /// This is equivalent to the UTS #39 definition: the
    /// [`skeleton`] of the string is confusable with a string
    /// whose resolved script set shares no script with the input.
    pub fn is_mixed_script_confusable(&self) -> bool {
        !self.has_restricted_char
            && self.resolved_script_set.is_empty()
            && self.confusable_chars().next().is_some()
            && self.uncovered_characters().next().is_none()
    }

    /// The [resolved script set](https://www.unicode.org/reports/tr39/#def-resolved-script-set)
    /// of the input string.
    ///
    /// An empty set means the string is mixed-script; a non-empty set means
    /// it is single-script (including ordinary Japanese Han/Kana mixtures).
    pub fn resolved_script_set(&self) -> AugmentedScriptSet {
        self.resolved_script_set
    }

    /// Whether the input contains at least one character restricted from
    /// identifier use by the General Security Profile.
    ///
    /// Restricted identifiers are out of scope for UTS #39 mixed-script
    /// confusable detection and always make
    /// [`MixedScriptConfusableReport::is_mixed_script_confusable`] return
    /// `false`. Inspect
    /// [`MixedScriptConfusableReport::restricted_characters`] for the exact
    /// characters.
    pub fn has_restricted_character(&self) -> bool {
        self.has_restricted_char
    }

    /// Iterate over every non-ignored character whose confusable prototype
    /// reaches a different non-ignored script.
    ///
    /// Common and Inherited characters are skipped because they carry no
    /// script of their own. The yielded records are the audit evidence for
    /// why a verdict was reached.
    pub fn confusable_chars(&self) -> ConfusableCharIter<'a> {
        ConfusableCharIter {
            chars: self.string.chars(),
            index: 0,
        }
    }

    /// Iterate over characters that fail the General Security Profile, as
    /// `(byte index, character)` pairs.
    pub fn restricted_characters(&self) -> RestrictedCharIter<'a> {
        RestrictedCharIter {
            chars: self.string.chars(),
            index: 0,
        }
    }

    /// Iterate over non-ignored characters lacking a cross-script confusable
    /// prototype, as `(byte index, character, script)` triples.
    ///
    /// Any such character prevents the mixed-script confusable verdict even
    /// when the rest of the string looks suspicious.
    pub fn uncovered_characters(&self) -> UncoveredCharIter<'a> {
        UncoveredCharIter {
            chars: self.string.chars(),
            index: 0,
        }
    }

    /// Compute the UTS #39 [`skeleton`] of the input string.
    ///
    /// Two strings are confusable exactly when their skeletons are equal;
    /// exposing it here lets callers cross-check the verdict. The returned
    /// iterator performs no allocation.
    pub fn skeleton(&self) -> impl Iterator<Item = char> + '_ {
        skeleton(self.string)
    }
}

/// Extension trait adding whole-string
/// [mixed-script confusable](https://www.unicode.org/reports/tr39/#Mixed_Script_Confusables)
/// detection to string slices.
pub trait MixedScriptConfusableDetection {
    /// Check whether this string is a mixed-script confusable and collect
    /// auditable evidence about the decision.
    ///
    /// See [`MixedScriptConfusableReport`] for the full semantics.
    fn mixed_script_confusable(&self) -> MixedScriptConfusableReport<'_>;
}

impl MixedScriptConfusableDetection for str {
    fn mixed_script_confusable(&self) -> MixedScriptConfusableReport<'_> {
        MixedScriptConfusableReport::scan(self)
    }
}

/// Convenience predicate for
/// [`MixedScriptConfusableReport::is_mixed_script_confusable`].
///
/// Use [`str::mixed_script_confusable`] directly when the resolved script
/// set, skeleton or per-character evidence are needed.
///
/// # Examples
///
/// ```
/// use unicode_security::is_mixed_script_confusable;
/// use unicode_security::MixedScriptConfusableDetection;
///
/// // Latin/Cyrillic spoof of "paypal": mixed-script and every non-Common
/// // character has a cross-script confusable prototype.
/// assert!(is_mixed_script_confusable("pаypаl"));
///
/// // Ordinary Japanese Han/Hiragana writing stays single-script through the
/// // augmented Jpan set, so it is never flagged.
/// assert!(!"冬の雪".mixed_script_confusable().is_mixed_script_confusable());
///
/// // Whole-script Cyrillic lookalikes are single-script, hence not
/// // mixed-script confusables even when the skeleton matches.
/// assert!(!is_mixed_script_confusable("раураӏ"));
/// ```
pub fn is_mixed_script_confusable(s: &str) -> bool {
    s.mixed_script_confusable().is_mixed_script_confusable()
}
