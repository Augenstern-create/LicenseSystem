pub(super) fn normalize(raw: &str) -> Option<String> {
    let normalized: String = raw
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if normalized.is_empty()
        || normalized.chars().all(|character| character == '0')
        || normalized.chars().all(|character| character == 'F')
        || matches!(
            normalized.as_str(),
            "UNKNOWN" | "NONE" | "DEFAULTSTRING" | "TOBEFILLEDBYOEM" | "NOTAPPLICABLE"
        )
    {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_and_case_do_not_change_identity() {
        assert_eq!(normalize(" ab-cd 12 "), Some("ABCD12".to_owned()));
        assert_eq!(normalize("AB:CD:12"), Some("ABCD12".to_owned()));
    }

    #[test]
    fn firmware_placeholders_are_rejected() {
        assert_eq!(normalize("To be filled by O.E.M."), None);
        assert_eq!(normalize("0000-0000"), None);
        assert_eq!(normalize("FF-FF-FF-FF"), None);
    }
}
