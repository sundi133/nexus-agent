use nexus_agent_core::{DetectionConfig, RansomwareTracker};

#[test]
fn synthetic_mass_change_reaches_high_severity() {
    let mut tracker = RansomwareTracker::new(DetectionConfig {
        window_ms: 10_000,
        max_processes: 32,
    });

    let mut assessment = tracker.observe_path(4242, 0, "/tmp/file-0", false);
    for i in 1..100 {
        assessment = tracker.observe_path(
            4242,
            i,
            &format!("/tmp/file-{i}"),
            i < 50,
        );
    }

    assert!(assessment.score >= 70);
    assert!(matches!(assessment.severity.as_str(), "high" | "critical"));
}

#[test]
fn repeated_writes_to_one_file_stay_low() {
    let mut tracker = RansomwareTracker::new(DetectionConfig {
        window_ms: 10_000,
        max_processes: 32,
    });

    let mut assessment = tracker.observe_path(4242, 0, "/tmp/same-file", false);
    for i in 1..100 {
        assessment = tracker.observe_path(4242, i, "/tmp/same-file", false);
    }

    assert_eq!(assessment.severity, "low");
}

#[test]
fn ordinary_small_unique_burst_stays_low() {
    let mut tracker = RansomwareTracker::new(DetectionConfig {
        window_ms: 10_000,
        max_processes: 32,
    });

    let mut assessment = tracker.observe_path(4242, 0, "/tmp/file-0", false);
    for i in 1..10 {
        assessment = tracker.observe_path(
            4242,
            i,
            &format!("/tmp/file-{i}"),
            false,
        );
    }

    assert_eq!(assessment.severity, "low");
}
