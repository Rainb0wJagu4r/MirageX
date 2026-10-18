use miragex::commands::updater::get_changelog_entries;

#[test]
fn test_changelog_entries_structure_and_integrity() {
    let entries = get_changelog_entries();
    assert!(!entries.is_empty(), "Changelog should contain version entries");

    // Must contain v4.0.2 as the current version
    let current = entries.iter().find(|e| e.is_current);
    assert!(current.is_some(), "There must be an entry marked as current");
    let current_entry = current.unwrap();
    assert_eq!(current_entry.version, "v4.0.2");
    assert!(!current_entry.highlights.is_empty());
    assert!(!current_entry.security_notes.is_empty());

    // Check that historical versions exist
    assert!(entries.iter().any(|e| e.version == "v4.0.0"));
    assert!(entries.iter().any(|e| e.version == "v3.5.0"));
}

#[test]
fn test_changelog_highlights_cover_core_features() {
    let entries = get_changelog_entries();
    let v402 = entries.iter().find(|e| e.version == "v4.0.2").unwrap();

    let all_text = v402.highlights.join(" ") + &v402.security_notes.join(" ");
    assert!(all_text.contains("Bóvedas") || all_text.contains(".wvault"));
    assert!(all_text.contains("Keyfile") || all_text.contains("VeraCrypt"));
    assert!(all_text.contains("Orientación") || all_text.contains("Guía"));
    assert!(all_text.contains("Velvet"));
}
