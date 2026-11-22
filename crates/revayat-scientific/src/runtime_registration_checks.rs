//! Registration decisions made before any child command can start.
use super::*;

fn pair() -> Result<(Peer, UnixStream)> {
    let (stream, caller) = UnixStream::pair()?;
    caller.set_nonblocking(true)?;
    Ok((
        Peer {
            stream,
            bytes: Vec::new(),
            id: None,
            done: false,
            stopped: false,
            may_clean: false,
            started: Instant::now(),
        },
        caller,
    ))
}

fn request(id: &str, parent: Option<&str>) -> Registration {
    Registration {
        token: "fixture".into(),
        id: id.into(),
        parent: parent.map(str::to_owned),
    }
}

#[test]
fn stopping_ancestor_declines_new_work_while_admitted_owners_finish() -> Result<()> {
    let mut accounting = Accounting::new();
    let mut active = Vec::new();
    for (id, parent) in [("root", None), ("child", Some("root"))] {
        let (mut peer, mut caller) = pair()?;
        dispatch_registration(&mut peer, &mut accounting, request(id, parent), "fixture")?;
        let mut reply = [0];
        caller.read_exact(&mut reply)?;
        assert_eq!(&reply, b"R");
        assert_eq!(peer.id.as_deref(), Some(id));
        active.push((peer, caller));
    }

    accounting.stopped("root")?;
    let (mut late, mut caller) = pair()?;
    dispatch_registration(
        &mut late,
        &mut accounting,
        request("new-work", Some("child")),
        "fixture",
    )?;
    assert!(late.done && late.id.is_none());
    drop(late);
    assert_eq!(caller.read(&mut [0])?, 0, "declined work received a reply");
    assert!(!accounting.descendants_settled("root"));
    accounting.stopped("child")?;
    accounting.done("child")?;
    accounting.retire("child")?;
    accounting.done("root")?;
    assert!(accounting.settled("root"));
    drop(active);
    Ok(())
}

#[test]
fn stopping_ancestor_does_not_exempt_invalid_registration() -> Result<()> {
    let mut accounting = Accounting::new();
    accounting.register("root", None)?;
    accounting.register("child", Some("root"))?;
    accounting.stopped("root")?;
    for (id, parent, token) in [
        ("child", "root", "fixture"),
        ("new-work", "missing", "fixture"),
        ("new-work", "child", "different-fixture"),
    ] {
        let (mut peer, mut caller) = pair()?;
        assert!(
            dispatch_registration(&mut peer, &mut accounting, request(id, Some(parent)), token,)
                .is_err()
        );
        assert!(peer.id.is_none());
        drop(peer);
        assert_eq!(caller.read(&mut [0])?, 0);
    }
    Ok(())
}
