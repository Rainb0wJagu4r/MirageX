use miragex::commands::updater::get_changelog_entries;

#[test]
fn test_changelog_entries_structure_and_integrity() {
    let entries = get_changelog_entries();
    assert!(!entries.is_empty(), "Changelog should contain version entries");

    // Must contain v4.1.0 as the current version
    let current = entries.iter().find(|e| e.is_current);
    assert!(current.is_some(), "There must be an entry marked as current");
    let current_entry = current.unwrap();
    assert_eq!(current_entry.version, "v4.1.0");
    assert!(!current_entry.highlights.is_empty());
    assert!(!current_entry.security_notes.is_empty());

    // Check that historical versions exist
    assert!(entries.iter().any(|e| e.version == "v4.0.2"));
    assert!(entries.iter().any(|e| e.version == "v4.0.0"));
    assert!(entries.iter().any(|e| e.version == "v3.5.0"));
}

#[test]
fn test_changelog_highlights_cover_core_features() {
    let entries = get_changelog_entries();
    let v410 = entries.iter().find(|e| e.version == "v4.1.0").unwrap();

    let all_text = v410.highlights.join(" ") + &v410.security_notes.join(" ");
    assert!(all_text.contains("Vigilante") || all_text.contains("VIGILANTE"));
    assert!(all_text.contains("Name Fuzzing") || all_text.contains("fuzzing"));
    assert!(all_text.contains("Respaldo"));
}
