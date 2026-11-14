//! Original event-classification and collection validation bodies, using the production API.
use super::*;

const IMAGE: &str = "C:\\fixed owned\\python.exe";
const START: &str = "2026-01-01T00:00:00Z";
const END: &str = "2026-01-01T00:00:01Z";
fn fixture_xml() -> String {
    format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='SideBySide'/><EventID>33</EventID><TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'/><Channel>Application</Channel></System><EventData><Data>{IMAGE}</Data><Data>Dependent Assembly Microsoft.Windows.Common-Controls,processorArchitecture=amd64 could not be found.</Data></EventData></Event>"
    )
}
fn encoded(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}
fn error_names(error: &anyhow::Error) -> Vec<String> {
    error.downcast_ref::<Failures>().map_or_else(
        || vec![error.to_string()],
        |group| group.errors.iter().flat_map(error_names).collect(),
    )
}
#[derive(Default)]
struct Fixture {
    bytes: Vec<u8>,
    count: usize,
    next: usize,
    log: Vec<&'static str>,
    closed: std::collections::BTreeSet<usize>,
    render_failure: bool,
    malformed_read: bool,
    release_failure: bool,
    close_failure: bool,
    forced_capacity: Option<u32>,
    allocation_failure: u8,
    cleared: bool,
    next_override: Option<Next>,
    fetch_failure: bool,
}
impl Fixture {
    fn new(xml: &str, count: usize) -> Self {
        Self {
            bytes: encoded(xml),
            count,
            ..Self::default()
        }
    }
}
impl EventApi for Fixture {
    fn query(&mut self) -> Result<usize> {
        self.log.push("query");
        Ok(100)
    }
    fn next(&mut self, query: usize, timeout: u32, value: &mut Next) -> Result<()> {
        ensure!(
            query == 100 && timeout == 1000,
            "event fixture query/timeout changed"
        );
        self.log.push("next");
        if let Some(overridden) = self.next_override {
            *value = overridden;
        } else {
            self.next += 1;
            if self.next > self.count {
                value.error = 259;
            } else {
                value.success = true;
                value.count = 1;
                value.handle = self.next;
            }
        }
        if self.fetch_failure {
            anyhow::bail!("private operation");
        }
        Ok(())
    }
    fn render(&mut self, item: usize, capacity: u32, data: usize) -> Result<Rendered> {
        ensure!(item > 0 && item <= self.count, "event fixture item changed");
        self.log.push(if capacity == 0 { "size" } else { "render" });
        ensure!(
            if capacity == 0 {
                data == 0
            } else {
                data == 200 && capacity as usize >= self.bytes.len()
            },
            "event fixture allocation changed"
        );
        if capacity != 0 && self.render_failure {
            *self.log.last_mut().unwrap() = "render-fail";
            anyhow::bail!("private render");
        }
        Ok(Rendered {
            success: capacity != 0,
            error: if capacity == 0 { 122 } else { 0 },
            bytes: if capacity == 0 {
                self.forced_capacity.unwrap_or(self.bytes.len() as u32)
            } else {
                self.bytes.len() as u32
            },
            properties: 0,
        })
    }
    fn allocate(&mut self, capacity: u32) -> Result<usize> {
        ensure!(
            capacity as usize >= self.bytes.len(),
            "event fixture capacity changed"
        );
        self.log.push("allocate");
        match self.allocation_failure {
            1 => anyhow::bail!("private allocation"),
            2 => Ok(0),
            3 => Ok(usize::MAX),
            _ => Ok(200),
        }
    }
    fn read(&mut self, data: usize, bytes: &mut [u8]) -> Result<()> {
        ensure!(
            data == 200 && bytes.len() == self.bytes.len(),
            "event fixture read span changed"
        );
        self.log.push("read");
        if self.malformed_read {
            let malformed =
                encoded(&fixture_xml().replace("<EventID>33</EventID>", "<EventID>-1</EventID>"));
            ensure!(
                malformed.len() == bytes.len(),
                "event malformed fixture size changed"
            );
            bytes.copy_from_slice(&malformed);
        } else {
            bytes.copy_from_slice(&self.bytes);
        }
        Ok(())
    }
    fn release(&mut self, data: usize, capacity: u32) -> Result<()> {
        ensure!(
            data == 200 && capacity as usize >= self.bytes.len(),
            "event fixture release span changed"
        );
        self.log.push("release");
        if self.release_failure {
            anyhow::bail!("private buffer release");
        }
        Ok(())
    }
    fn close(&mut self, handle: usize) -> Result<()> {
        ensure!(
            (handle == 100 || handle > 0 && handle <= self.count.max(1))
                && self.closed.insert(handle),
            "event handle ownership duplicated"
        );
        self.log.push(if handle == 100 {
            "query-close"
        } else {
            "event-close"
        });
        if self.close_failure {
            anyhow::bail!(if handle == 100 {
                "private query close"
            } else {
                "private event close"
            });
        }
        Ok(())
    }
    fn decoded_bytes_cleared(&mut self, bytes: &[u8]) {
        self.cleared = bytes.iter().all(|byte| *byte == 0);
    }
}

/// Source counterpart of StartupActivationEvents.CheckValidation and its CheckCollection root.
pub fn check_startup_events_validation() -> Result<()> {
    // Actual XML adapter semantics preserve the raw nonzero observation. The frozen generic
    // model still refuses it; neither operation invents a zero property count.
    let raw = Rendered {
        success: false,
        error: 122,
        bytes: 1812,
        properties: 1,
    };
    ensure!(
        xml_required_bytes(raw)? == 1812 && required_bytes(raw).is_err(),
        "XML sizing confused string bytes with EVT_VARIANT properties"
    );
    let done = Rendered {
        success: true,
        error: 0,
        bytes: 10,
        properties: 1,
    };
    ensure!(
        xml_rendered_bytes(done, 10)? == 10 && done.properties == 1,
        "XML rendering replaced raw property observation"
    );
    for invalid in [
        Rendered { bytes: 3, ..raw },
        Rendered { error: 5, ..raw },
        Rendered {
            success: true,
            ..raw
        },
    ] {
        ensure!(
            xml_required_bytes(invalid).is_err(),
            "invalid native XML sizing accepted"
        );
    }
    ensure!(
        xml_rendered_bytes(Rendered { bytes: 12, ..done }, 10).is_err()
            && xml_rendered_bytes(
                Rendered {
                    success: false,
                    ..done
                },
                10
            )
            .is_err(),
        "invalid native XML render span accepted"
    );

    ensure!(
        query_text(START, END)?
            == "*[System[Provider[@Name='SideBySide'] and TimeCreated[@SystemTime>='2026-01-01T00:00:00Z' and @SystemTime<='2026-01-01T00:00:01Z']]]",
        "event fixed query contract differs"
    );
    query_text(START, "2026-01-01T00:05:00Z")?;
    for (start, end) in [
        (START, "2026-01-01T00:05:00.0000001Z"),
        (END, START),
        ("2026-01-01T00:00:00+00:00", END),
        ("2026-01-01T00:00:00Z']", END),
    ] {
        ensure!(
            query_text(start, end).is_err(),
            "event invalid query window accepted"
        );
    }
    check_classification_validation()?;
    for count in [0, 1, 16, 17] {
        let calls = std::cell::Cell::new(0);
        let consumed = std::cell::Cell::new(0);
        let result = enumerate(
            || {
                calls.set(calls.get() + 1);
                Ok(calls.get() <= count)
            },
            || {
                consumed.set(consumed.get() + 1);
                Ok(())
            },
        );
        ensure!(
            calls.get() == (count + 1).min(17)
                && consumed.get() == count.min(16)
                && result.is_err() == (count == 17),
            "event enumeration bound differs"
        );
    }
    let mut api = Fixture {
        next_override: Some(Next {
            error: 259,
            ..Next::default()
        }),
        ..Fixture::default()
    };
    ensure!(
        !use_next(&mut api, 100, 1000, |_, _| anyhow::bail!(
            "unexpected event"
        ))?,
        "event end was consumed"
    );
    api.next_override = Some(Next {
        success: true,
        count: 1,
        handle: 1,
        ..Next::default()
    });
    let uses = std::cell::Cell::new(0);
    ensure!(
        use_next(&mut api, 100, 1000, |_, _| {
            uses.set(uses.get() + 1);
            Ok(())
        })? && uses.get() == 1
            && api
                .log
                .iter()
                .filter(|item| **item == "event-close")
                .count()
                == 1,
        "event owned next lifetime differs"
    );
    // Each invalid output gets a separate owner, preventing a test double from masking double close.
    let mut closes = 1;
    for value in [
        Next {
            error: 1460,
            ..Next::default()
        },
        Next {
            success: true,
            ..Next::default()
        },
        Next {
            error: 259,
            handle: 1,
            ..Next::default()
        },
        Next {
            success: true,
            count: 2,
            handle: 1,
            ..Next::default()
        },
    ] {
        let mut api = Fixture {
            next_override: Some(value),
            ..Fixture::default()
        };
        ensure!(
            use_next(&mut api, 100, 1000, |_, _| {
                uses.set(uses.get() + 1);
                Ok(())
            })
            .is_err(),
            "event invalid next accepted"
        );
        closes += api
            .log
            .iter()
            .filter(|item| **item == "event-close")
            .count();
    }
    ensure!(
        closes == 3 && uses.get() == 1,
        "event invalid-output cleanup differs"
    );
    let mut api = Fixture {
        next_override: Some(Next {
            handle: 1,
            ..Next::default()
        }),
        fetch_failure: true,
        close_failure: true,
        ..Fixture::default()
    };
    let error = use_next(&mut api, 100, 1000, |_, _| Ok(())).unwrap_err();
    ensure!(
        error_names(&error) == ["private operation", "private event close"],
        "event partial acquisition errors differ"
    );
    for bytes in [4, 65536] {
        ensure!(
            required_bytes(Rendered {
                error: 122,
                bytes,
                ..Rendered::default()
            })? == bytes,
            "event required-byte boundary differs"
        );
    }
    for bytes in [0, 2, 5, 65538] {
        ensure!(
            required_bytes(Rendered {
                error: 122,
                bytes,
                ..Rendered::default()
            })
            .is_err(),
            "event required-byte invalid size accepted"
        );
    }
    for value in [
        Rendered {
            success: true,
            bytes: 8,
            ..Rendered::default()
        },
        Rendered {
            error: 5,
            bytes: 8,
            ..Rendered::default()
        },
        Rendered {
            error: 122,
            bytes: 8,
            properties: 1,
            ..Rendered::default()
        },
    ] {
        ensure!(
            required_bytes(value).is_err(),
            "event invalid sizing status accepted"
        );
    }
    let text = encoded("<x/>");
    ensure!(
        decode(&text, text.len() as u32, text.len() as u32, 0)? == "<x/>",
        "event literal UTF-16 decode differs"
    );
    ensure!(
        decode(&text, text.len() as u32 - 1, text.len() as u32, 0).is_err()
            && decode(&text, text.len() as u32, text.len() as u32, 1).is_err()
            && decode(&[0; 4], 4, 4, 0).is_err(),
        "event invalid UTF-16 output accepted"
    );
    for bytes in [&[0, 0xd8, 0, 0][..], &[0x41, 0, 0x42, 0][..]] {
        ensure!(
            decode(bytes, 4, 4, 0).is_err(),
            "event malformed native UTF-16 accepted"
        );
    }
    let private = safe(anyhow::anyhow!("private operation"), "event-evidence");
    let carrier = private
        .downcast_ref::<crate::windows_security::sxs::PrivateFailure>()
        .ok_or_else(|| anyhow::anyhow!("event private carrier missing"))?;
    ensure!(
        carrier.original().to_string() == "private operation"
            && std::error::Error::source(carrier).is_none()
            && !private.to_string().contains("private"),
        "event private carrier disclosed cause"
    );
    check_collection_validation()
}
fn check_collection_validation() -> Result<()> {
    let xml = fixture_xml();
    for mode in 0..3 {
        let mut api = Fixture::new(&xml, 1);
        api.render_failure = mode != 1;
        api.malformed_read = mode == 1;
        api.release_failure = mode == 2;
        api.close_failure = true;
        let error = collect(&mut api, IMAGE, START, END, || Ok(()), || 1000).unwrap_err();
        let names = error_names(&error);
        ensure!(
            names.len() == if mode == 2 { 4 } else { 3 },
            "event collection error count differs"
        );
        ensure!(
            if mode == 1 {
                error.downcast_ref::<Failures>().unwrap().errors[0]
                    .is::<crate::windows_security::sxs::PrivateFailure>()
            } else {
                names[0] == "private render"
            },
            "event collection primary error differs"
        );
        let close_index = if mode == 2 { 2 } else { 1 };
        ensure!(
            (mode != 2 || names[1] == "private buffer release")
                && names[close_index] == "private event close"
                && names[close_index + 1] == "private query close",
            "event independent cleanup error order differs"
        );
        let expected: &[&str] = if mode == 1 {
            &[
                "query",
                "next",
                "size",
                "allocate",
                "render",
                "read",
                "release",
                "event-close",
                "query-close",
            ]
        } else {
            &[
                "query",
                "next",
                "size",
                "allocate",
                "render-fail",
                "release",
                "event-close",
                "query-close",
            ]
        };
        ensure!(
            api.log == expected && api.cleared,
            "event release order or managed scrub differs"
        );
    }
    for count in [0, 1, 16, 17] {
        let mut api = Fixture::new(&xml, count);
        let result = collect(&mut api, IMAGE, START, END, || Ok(()), || 1000);
        ensure!(
            result.is_err() == (count == 17)
                && api.log.iter().filter(|item| **item == "render").count() == count.min(16)
                && api
                    .log
                    .iter()
                    .filter(|item| **item == "event-close")
                    .count()
                    == count
                && api
                    .log
                    .iter()
                    .filter(|item| **item == "query-close")
                    .count()
                    == 1
                && api.log.last() == Some(&"query-close"),
            "event collection limit or ownership differs"
        );
        if count == 17 {
            ensure!(
                api.log[api.log.len() - 3..] == ["next", "event-close", "query-close"],
                "event overflow rendered its extra item"
            );
        } else {
            let lines = result?;
            ensure!(
                lines.len() == count + 1
                    && lines[count]
                        .contains(&format!("scanned_count={count} selected_count={count}")),
                "event collection summary differs"
            );
        }
    }
    let mut api = Fixture::new(&xml.replace(IMAGE, &(IMAGE.to_owned() + ".other")), 1);
    let lines = collect(&mut api, IMAGE, START, END, || Ok(()), || 1000)?;
    ensure!(
        lines.len() == 1
            && lines[0].contains("scanned_count=1 selected_count=0 status=inconclusive_no_match"),
        "event no-match claimed evidence"
    );
    let mut api = Fixture::new(&xml, 5);
    api.forced_capacity = Some(65536);
    ensure!(
        collect(&mut api, IMAGE, START, END, || Ok(()), || 1000).is_err(),
        "event aggregate allocation budget accepted"
    );
    for (name, expected) in [
        ("size", 5),
        ("allocate", 4),
        ("render", 4),
        ("release", 4),
        ("event-close", 5),
        ("query-close", 1),
    ] {
        ensure!(
            api.log.iter().filter(|item| **item == name).count() == expected,
            "event aggregate allocation accounting differs"
        );
    }
    ensure!(
        api.log.last() == Some(&"query-close"),
        "event budget failure leaked query"
    );
    for mode in 1..=3 {
        let mut api = Fixture::new(&xml, 1);
        api.allocation_failure = mode;
        ensure!(
            collect(&mut api, IMAGE, START, END, || Ok(()), || 1000).is_err()
                && api.log
                    == [
                        "query",
                        "next",
                        "size",
                        "allocate",
                        "event-close",
                        "query-close"
                    ],
            "event allocation failure skipped independent handle cleanup"
        );
    }
    Ok(())
}
fn check_classification_validation() -> Result<()> {
    let xml = fixture_xml();
    let line = classify_event(&xml, IMAGE, START, END)?
        .ok_or_else(|| anyhow::anyhow!("event fixture did not select owned image"))?;
    ensure!(
        line.contains("event_id=33 matched_owned_image=True")
            && line.contains("dependent_assembly_not_found=True")
            && line.contains("common_controls=True")
            && line.contains("amd64=True")
            && !line.contains(IMAGE)
            && !line.contains("Dependent Assembly"),
        "event fixed classification differs"
    );
    ensure!(
        classify_event(
            &xml.replace(IMAGE, &(IMAGE.to_owned() + ".other")),
            IMAGE,
            START,
            END
        )?
        .is_none()
            && classify_event(
                &xml.replace(IMAGE, &IMAGE.to_uppercase()),
                IMAGE,
                START,
                END
            )?
            .as_deref()
                == Some(&line),
        "event image identity differs"
    );
    let provider = "<Provider Name='SideBySide'/>";
    let time = "<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'/>";
    let extended = xml.replace(provider, "<Provider Name='SideBySide' Guid='{00000000-0000-0000-0000-000000000001}' EventSourceName='SideBySide'/>")
        .replace("<EventID>", "<EventID Qualifiers='0'>");
    ensure!(
        classify_event(&extended, IMAGE, START, END)?.as_deref() == Some(&line),
        "event optional metadata differs"
    );
    for invalid in [
        xml.replace("SideBySide", "Other"), xml.replace("Application", "System"),
        xml.replace("http://schemas.microsoft.com/win/2004/08/events/event", "urn:other"),
        xml.replace("<EventID>33</EventID>", "<EventID>-1</EventID>"),
        xml.replace("<EventID>33</EventID>", "<EventID><Nested>33</Nested></EventID>"),
        xml.replace("<Channel>Application</Channel>", "<Channel><Nested>Application</Nested></Channel>"),
        xml.replace(provider, "<Provider Name='SideBySide'><Nested/></Provider>"),
        xml.replace(time, "<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'><Nested/></TimeCreated>"),
        xml.replace("<EventID>33</EventID>", "<EventID><Foreign xmlns='urn:other'>33</Foreign></EventID>"),
        xml.replace("<Channel>Application</Channel>", "<Channel><Foreign xmlns='urn:other'>Application</Foreign></Channel>"),
        xml.replace(provider, "<Provider Name='SideBySide'><Foreign xmlns='urn:other'/></Provider>"),
        xml.replace(time, "<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'><Foreign xmlns='urn:other'/></TimeCreated>"),
        xml.replace(provider, "<Provider Name='SideBySide' Unknown='value'/>"),
        xml.replace("<EventID>", "<EventID Qualifiers='65536'>"), xml.replace("<EventID>33</EventID>", "<EventID>65536</EventID>"),
        xml.replace("<Channel>", "<Channel Unknown='value'>"), xml.replace("<TimeCreated ", "<TimeCreated Unknown='value' "),
        xml.replace("00:00:00.5000000Z", "00:00:02.5000000Z"),
        xml.replace("</EventData>", &format!("<Data>{IMAGE}</Data></EventData>")),
        format!("<!DOCTYPE Event [<!ENTITY x 'private'>]>{xml}"), xml.replace("</EventData>", "<Other/></EventData>"),
        xml.replace(&format!("<Data>{IMAGE}"), &format!("<Data><Nested/>{IMAGE}")), "x".repeat(32769),
    ] {ensure!(classify_event(&invalid, IMAGE, START, END).is_err(), "event malformed XML accepted");}
    let unknown = xml.replace("Dependent Assembly Microsoft.Windows.Common-Controls,processorArchitecture=amd64 could not be found.", "private unknown payload");
    let line = classify_event(&unknown, IMAGE, START, END)?.unwrap();
    ensure!(
        line.contains("dependent_assembly_not_found=False") && !line.contains("private"),
        "event unknown payload disclosed details"
    );
    Ok(())
}
