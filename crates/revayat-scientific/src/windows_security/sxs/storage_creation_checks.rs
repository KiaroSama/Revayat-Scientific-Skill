use super::*;
use std::{
    cell::Cell,
    mem::{offset_of, size_of},
    sync::Arc,
};
const FOLDER: &str = r"D:\sxs-trace-0123456789abcdef0123456789abcdef";
const DEVICE: &str = "\\Device\\HarddiskVolume12\0\0";
#[derive(Clone, Debug)]
struct Failure(Arc<()>);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private-storage-sentinel")
    }
}
impl std::error::Error for Failure {}
fn error(id: &Arc<()>) -> anyhow::Error {
    Failure(id.clone()).into()
}
fn same(error: &anyhow::Error, id: &Arc<()>) -> bool {
    error
        .downcast_ref::<Failure>()
        .is_some_and(|error| Arc::ptr_eq(&error.0, id))
}
struct Fixture {
    mapping: String,
    length: Option<usize>,
    queries: usize,
    created: usize,
    closed: usize,
}
impl Fixture {
    fn new() -> Self {
        Self {
            mapping: DEVICE.into(),
            length: None,
            queries: 0,
            created: 0,
            closed: 0,
        }
    }
}
impl CreationIo for Fixture {
    fn query(&mut self, drive: &str, output: &mut [u16; 512]) -> Result<usize> {
        self.queries += 1;
        ensure!(
            drive == "D:" && output.len() == 512,
            "storage device query ABI differs"
        );
        for (index, unit) in self.mapping.encode_utf16().enumerate() {
            output[index] = unit;
        }
        Ok(self.length.unwrap_or(self.mapping.encode_utf16().count()))
    }
    fn create(&mut self, request: &mut NativeCreation) -> Result<i32> {
        self.created += 1;
        let args = request.parameters();
        let attributes = request.attributes();
        ensure!(
            request.within(attributes.name, size_of::<UnicodeString>(), 8)
                && request.within(attributes.descriptor, 4, 8),
            "native attributes point outside retained allocation"
        );
        let text = unsafe { (attributes.name as *const UnicodeString).read() };
        ensure!(
            args.access == 0x120080
                && attributes.length == 48
                && attributes.root == 0
                && attributes.flags == 0x1040
                && attributes.qos == 0
                && args.allocation == 0
                && args.flags == 0x80
                && args.share == 0
                && args.disposition == 2
                && args.options == 0x21
                && args.ea == 0
                && args.ea_length == 0,
            "storage create argument ABI differs"
        );
        ensure!(
            request.handle() == 0 && request.io().status() == -1 && request.io().information == 0,
            "storage output sentinels differ"
        );
        ensure!(
            text.length == 134
                && text.maximum == 136
                && request.within(text.buffer, usize::from(text.maximum), 2)
                && unsafe {
                    (text.buffer as *const u16)
                        .add(usize::from(text.length) / 2)
                        .read()
                } == 0
                && String::from_utf16(unsafe {
                    std::slice::from_raw_parts(
                        text.buffer as *const u16,
                        usize::from(text.length) / 2,
                    )
                })? == r"\Device\HarddiskVolume12\sxs-trace-0123456789abcdef0123456789abcdef"
                && unsafe { std::slice::from_raw_parts(attributes.descriptor as *const u8, 4) }
                    == [1, 2, 3, 4],
            "storage native Unicode/descriptor bytes differ"
        );
        let handle = request.handle_slot();
        let io = request.io_slot();
        ensure!(
            request.within(handle as usize, 8, 8)
                && request.within(io as usize, 16, 8)
                && io as usize == handle as usize + 8,
            "native output slots differ"
        );
        unsafe {
            handle.write(17);
            io.write(IoStatus {
                value: IoValue {
                    pointer: 0xf123456700000000,
                },
                information: 2,
            });
        }
        Ok(0)
    }
    fn close(&mut self, handle: usize) -> Result<()> {
        ensure!(handle == 17, "storage closed an unowned handle");
        self.closed += 1;
        Ok(())
    }
    fn fatal(&mut self) -> Result<()> {
        anyhow::bail!("unexpected pending")
    }
}
pub fn check_validation() -> Result<()> {
    ensure!(
        size_of::<usize>() == 8,
        "native storage source requires x64"
    );
    ensure!(
        size_of::<UnicodeString>() == 16
            && [
                offset_of!(UnicodeString, length),
                offset_of!(UnicodeString, maximum),
                offset_of!(UnicodeString, buffer)
            ] == [0, 2, 8]
            && size_of::<Attributes>() == 48
            && [
                offset_of!(Attributes, length),
                offset_of!(Attributes, root),
                offset_of!(Attributes, name),
                offset_of!(Attributes, flags),
                offset_of!(Attributes, descriptor),
                offset_of!(Attributes, qos)
            ] == [0, 8, 16, 24, 32, 40]
            && size_of::<IoStatus>() == 16
            && offset_of!(IoStatus, value) == 0
            && offset_of!(IoStatus, information) == 8
            && offset_of!(IoValue, status) == 0
            && offset_of!(IoValue, pointer) == 0,
        "native storage x64 layout differs"
    );
    let mapping = DEVICE.encode_utf16().collect::<Vec<_>>();
    ensure!(
        native_path(FOLDER, &mapping)?
            == r"\Device\HarddiskVolume12\sxs-trace-0123456789abcdef0123456789abcdef",
        "storage native path differs"
    );
    for mapping in [
        "",
        "\\Device\\HarddiskVolume12\0",
        "\\Device\\HarddiskVolume12\0prior\0\0",
        "\\Device\\HarddiskVolume\0\0",
        "\\Device\\HarddiskVolume1\\bad\0\0",
        "\\??\\D:\0\0",
        "\\device\\HarddiskVolume1\0\0",
        "\\Device\\HarddiskVolume123456789012345678901\0\0",
    ] {
        let mut io = Fixture::new();
        io.mapping = mapping.into();
        let mut descriptor = [1, 2, 3, 4];
        ensure!(
            create_fixed(FOLDER, &mut descriptor, &mut io).is_err() && io.created == 0,
            "foreign device mapping reached native create"
        );
    }
    for length in [0, 1, 513, u32::MAX as usize] {
        let mut io = Fixture::new();
        io.length = Some(length);
        ensure!(
            create_fixed(FOLDER, &mut [1, 2, 3, 4], &mut io).is_err() && io.created == 0,
            "oversize device query count reached create"
        );
    }
    for folder in [
        FOLDER.to_lowercase(),
        format!("{FOLDER}\\extra"),
        FOLDER.replace("sxs-trace", "other-dir"),
        FOLDER.replace('f', "G"),
    ] {
        let mut io = Fixture::new();
        ensure!(
            create_fixed(&folder, &mut [1, 2, 3, 4], &mut io).is_err() && io.queries == 0,
            "invalid fixed folder queried device"
        );
    }
    require_result(
        0,
        IoStatus {
            value: IoValue { pointer: 0 },
            information: 2,
        },
        17,
    )?;
    for status in [0x103, 0, 0xc0000035u32 as i32, 0x80000005u32 as i32] {
        let fatal = Cell::new(false);
        let finalized = Cell::new(false);
        let reads = Cell::new(0);
        let mut pending = false;
        let result = complete(
            status,
            || {
                reads.set(reads.get() + 1);
                Ok(IoStatus {
                    value: IoValue {
                        pointer: if status == 0 { 0x103 } else { 0 },
                    },
                    information: 2,
                })
            },
            || Ok(17),
            || {
                fatal.set(true);
                Ok(())
            },
            |operation| {
                finalized.set(true);
                operation
            },
            &mut pending,
        );
        ensure!(
            result.is_err()
                && fatal.get() == matches!(status, 0x103 | 0)
                && finalized.get() != fatal.get()
                && reads.get() == usize::from(status != 0x103),
            "pending completion read/finalization order differs"
        );
    }
    for (status, handle, information) in [(0, 0, 2), (0, usize::MAX, 2), (-1, 17, 2), (0, 17, 1)] {
        ensure!(
            require_result(
                0,
                IoStatus {
                    value: IoValue { status },
                    information
                },
                handle
            )
            .is_err(),
            "invalid creation output accepted"
        );
    }
    let mut io = Fixture::new();
    let mut descriptor = [1, 2, 3, 4];
    create_fixed(FOLDER, &mut descriptor, &mut io)?;
    ensure!(
        io.created == 1 && io.closed == 1 && descriptor == [0; 4],
        "native create/close or descriptor zeroing differs"
    );
    let first = Arc::new(());
    let cleanup = Arc::new(());
    let order = RefCell::new(String::new());
    let caught = release(
        Err(error(&first)),
        17,
        |_| {
            order.borrow_mut().push('c');
            Err(error(&cleanup))
        },
        vec![
            Box::new(|| {
                order.borrow_mut().push('a');
                Err(error(&cleanup))
            }),
            Box::new(|| {
                order.borrow_mut().push('b');
                Ok(())
            }),
        ],
    )
    .unwrap_err();
    let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        *order.borrow() == "cab"
            && errors.len() == 3
            && same(&errors[0], &first)
            && same(&errors[1], &cleanup),
        "storage release cause/attempt order differs"
    );
    Ok(())
}
