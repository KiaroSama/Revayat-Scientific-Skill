#[cfg(unix)]
mod unix {
    use revayat_scientific::runtime::owner::Accounting;

    #[test]
    fn registration_precedes_spawn_and_parent_waits_for_every_nested_completion() {
        let mut owners = Accounting::new();
        owners.register("root", None).unwrap();
        owners.register("child", Some("root")).unwrap();
        owners.register("grandchild", Some("child")).unwrap();
        owners.stopped("root").unwrap();
        assert!(!owners.descendants_settled("root"));
        assert!(owners.done("root").is_err());
        assert!(owners.register("late", Some("child")).is_err());
        owners.stopped("child").unwrap();
        owners.stopped("grandchild").unwrap();
        owners.done("grandchild").unwrap();
        owners.retire("grandchild").unwrap();
        assert!(owners.descendants_settled("child"));
        owners.done("child").unwrap();
        owners.retire("child").unwrap();
        assert!(owners.descendants_settled("root"));
        owners.done("root").unwrap();
        assert!(owners.settled("root"));
    }

    #[test]
    fn completed_children_retire_without_limiting_total_sequential_work() {
        let mut owners = Accounting::new();
        owners.register("root", None).unwrap();
        for index in 0..1024 {
            let id = format!("child-{index}");
            owners.register(&id, Some("root")).unwrap();
            owners.stopped(&id).unwrap();
            owners.done(&id).unwrap();
            owners.retire(&id).unwrap();
        }
        for index in 0..255 {
            owners
                .register(&format!("active-{index}"), Some("root"))
                .unwrap();
        }
        assert!(owners.register("over-cap", Some("root")).is_err());
        assert!(!owners.settled("root"));
    }

    #[test]
    fn cleanup_budget_starts_on_stop_and_uses_the_earliest_ancestor_cutoff() {
        use std::time::{Duration, Instant};
        let mut owners = Accounting::new();
        owners.register("root", None).unwrap();
        owners.register("child", Some("root")).unwrap();
        assert!(owners.cleanup_deadline("child").unwrap().is_none());
        let child_cutoff = Instant::now() + Duration::from_secs(30);
        owners.stop_at("child", child_cutoff).unwrap();
        assert_eq!(
            owners.cleanup_deadline("child").unwrap(),
            Some(child_cutoff)
        );
        let root_cutoff = Instant::now() + Duration::from_secs(1);
        owners.stop_at("root", root_cutoff).unwrap();
        assert_eq!(owners.cleanup_deadline("child").unwrap(), Some(root_cutoff));
    }

    #[test]
    fn actual_interactive_timeout_remains_failure_on_repeated_finalization() {
        use revayat_scientific::runtime::{CommandSpec, owner::Interactive};
        use std::time::{Duration, Instant};
        let mut spec = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-test-tool")).args(["silent"]);
        spec.timeout = Duration::from_millis(100);
        let mut owner = Interactive::spawn(&spec).unwrap();
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(150) {
            let _ = owner.try_wait();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(owner.finish().is_err());
        assert!(
            owner.finish().is_err(),
            "settled failure must not become success"
        );
    }

    #[test]
    fn expired_container_cleanup_retains_receipt_and_drop_does_not_retry() {
        use revayat_scientific::tex_supervisor::ContainerScope;
        use std::time::{Duration, Instant};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut scope = ContainerScope::create(&root).unwrap();
        let path = scope.directory.clone();
        std::fs::write(
            path.join("container-invalid.json"),
            b"retain for deliberate recovery",
        )
        .unwrap();
        assert!(
            scope
                .finish_until(Instant::now() - Duration::from_millis(1))
                .is_err()
        );
        drop(scope);
        assert!(path.join("container-invalid.json").is_file());
    }

    #[test]
    fn missing_duplicate_foreign_parent_or_crashed_owner_is_not_cleanup() {
        let mut owners = Accounting::new();
        owners.register("root", None).unwrap();
        assert!(owners.register("child", Some("unknown")).is_err());
        owners.register("child", Some("root")).unwrap();
        assert!(owners.register("child", Some("root")).is_err());
        assert!(owners.done("root").is_err());
        owners.stopped("root").unwrap();
        owners.stopped("child").unwrap();
        owners.failed();
        assert!(owners.done("child").is_err());
        assert!(!owners.settled("root"));
    }
}
