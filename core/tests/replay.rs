use nexus_agent_core::{assess_ransomware, ProcessWindow};

#[test]
fn synthetic_mass_change_reaches_high_severity() {
    let mut window = ProcessWindow::new(4242, 0);
    for i in 0..100 {
        window.observe_file_change(i, i < 50);
    }
    let assessment = assess_ransomware(&window.features());
    assert!(assessment.score >= 70);
    assert!(matches!(assessment.severity.as_str(), "high" | "critical"));
}

#[test]
fn ordinary_small_burst_stays_low() {
    let mut window = ProcessWindow::new(4242, 0);
    for i in 0..10 {
        window.observe_file_change(i, false);
    }
    let assessment = assess_ransomware(&window.features());
    assert_eq!(assessment.severity, "low");
}
