//! Whole-worker-only scratch recovery. No observation/actor retirement can detach a disk.
use super::{
    NativeRunOwner,
    scratch_access::{self as access, Owned},
    scratch_disk::{self as disk, Created, Intent, Mount, Ready},
    scratch_layout as layout,
};
use anyhow::{Context, Result, ensure};
use std::path::Path;
use windows::Win32::{
    Foundation::HANDLE,
    Storage::Vhd::{DETACH_VIRTUAL_DISK_FLAG_NONE, DetachVirtualDisk},
};

fn pending(state: &Path) -> Result<()> {
    // Root coordinates exact trace/registry recovery first. Unrecognized intent is retained.
    for entry in std::fs::read_dir(state)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("owned recovery entry encoding differs"))?;
        ensure!(
            !(matches!(name, "sxs-trace.intent" | "sxs-trace.bound")
                || name.ends_with(".receipt")
                    && (name.contains("trace")
                        || name.starts_with("registry-policy")
                        || name.starts_with("loader-snaps"))),
            "trace/registry/loader recovery remains pending before scratch detach"
        );
    }
    Ok(())
}
fn no_policy_receipt(state: &Path) -> Result<()> {
    for name in [
        "scratch-volume-policy.receipt",
        "scratch-volume-diagnostic.receipt",
        "scratch-volume-supported.receipt",
    ] {
        ensure!(
            !state.join(name).try_exists()?,
            "scratch policy restoration requires its original attached volume"
        );
    }
    Ok(())
}
/// Only runtime's opaque whole-worker capability authorizes this recovery boundary.
pub fn recover_scratch(
    owner: &NativeRunOwner,
    proof: &crate::runtime::ReapedProcessTree,
) -> Result<()> {
    proof.require_binding(owner.recovery_binding())?;
    owner.view.require()?;
    let view = &owner.view;
    let state = view.state_path();
    pending(state)?;
    let host = crate::windows_security::sxs::current_user_sid()?;
    let intent: Option<Intent> = access::read_json(state, &host, "scratch-disk.intent")?;
    let image_path = state.join("scratch.vhdx");
    let Some(intent) = intent else {
        ensure!(
            !image_path.try_exists()?,
            "scratch image lacks durable creation intent"
        );
        for entry in std::fs::read_dir(state)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("scratch recovery entry encoding differs"))?;
            ensure!(
                !name.starts_with("scratch-disk.") && !name.starts_with("scratch-volume-"),
                "scratch recovery records lack creation intent"
            );
        }
        return Ok(());
    };
    ensure!(
        intent.version == 1
            && intent.host == host
            && intent.run == view.run_id()
            && intent.package == view.package_sid()
            && intent.state == view.state_identity(),
        "scratch creation intent belongs to a different run"
    );
    layout::guid(&intent.vhd)?;
    layout::guid(&intent.gpt)?;
    layout::guid(&intent.partition)?;
    let created: Option<Created> = access::read_json(state, &host, "scratch-disk.created")?;
    let detached: Option<Created> = access::read_json(state, &host, "scratch-disk.detached")?;
    if !image_path.try_exists()? {
        if let Some(detached) = detached {
            ensure!(
                created
                    .as_ref()
                    .is_some_and(|created| created.image == detached.image),
                "scratch detached completion identity differs"
            );
            no_policy_receipt(state)?;
            return Ok(());
        }
        ensure!(
            created.is_none()
                && access::read_record(state, &host, "scratch-disk.attach-intent")?.is_none()
                && access::read_record(state, &host, "scratch-disk.layout-intent")?.is_none()
                && access::read_record(state, &host, "scratch-disk.volume")?.is_none()
                && access::read_record(state, &host, "scratch-disk.mount-intent")?.is_none()
                && access::read_record(state, &host, "scratch-disk.ready")?.is_none(),
            "scratch image disappeared before qualified detach"
        );
        no_policy_receipt(state)?;
        return Ok(());
    }
    crate::windows_security::plain_path(&image_path)?;
    let mut privilege = access::ManageVolume::acquire()?;
    // DELETE is deliberately absent while the virtual-disk provider can still hold the file.
    let mut image = match Owned::open(&image_path, 0x20080, 3, 0x200000).context(
        "scratch_recovery phase=image-pin desired=0x00020080 share=0x00000003 before_detach=True",
    ) {
        Ok(image) => image,
        Err(primary) => return access::combine(Err(primary), privilege.close()),
    };
    let result = (|| {
        access::require_private(image.0, &host)?;
        let id = access::identity(image.0, false)?;
        if let Some(created) = &created {
            ensure!(id == created.image, "scratch image identity was replaced");
        }
        let created = Created { image: id };
        let mut virtual_disk = disk::open_virtual(&image_path, &intent)
            .context("scratch_recovery phase=provider-open metadata_pin=True")?;
        let result = (|| {
            disk::require_image(&image_path, image.0, id, &host)?;
            let mount: Option<Mount> =
                access::read_json(state, &host, "scratch-disk.mount-intent")?;
            let volume: Option<layout::VolumeBinding> =
                access::read_json(state, &host, "scratch-disk.volume")?;
            let ready: Option<Ready> = access::read_json(state, &host, "scratch-disk.ready")?;
            if let Some(path) = disk::attached_path(virtual_disk.0)? {
                ensure!(
                    detached.is_none(),
                    "detached scratch image was attached again"
                );
                let (mut raw, number) = layout::disk(&path)?;
                let result = (|| {
                    if let Some(volume) = &volume {
                        ensure!(
                            volume.disk == number
                                && volume.gpt == intent.gpt
                                && volume.partition_id == intent.partition,
                            "scratch volume durable disk/GPT identity differs"
                        );
                        layout::require_disk_binding(raw.0, volume)?;
                        let mut handle = layout::volume(volume)?;
                        handle.close()?;
                    }
                    if let Some(mount) = &mount {
                        let volume = volume.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("scratch mount lacks durable volume identity")
                        })?;
                        ensure!(
                            serde_json::to_vec(&mount.binding)? == serde_json::to_vec(volume)?,
                            "scratch mount/volume records differ"
                        );
                        layout::drive_root(&mount.root)?;
                        if let Some(ready) = ready {
                            ensure!(
                                serde_json::to_vec(&ready.mount)? == serde_json::to_vec(mount)?,
                                "scratch ready/mount records differ"
                            );
                            if layout::mounted(&mount.root)?.is_some() {
                                let mut root = Owned::open(&mount.root, 0x80, 3, 0x2200000)
                                    .context("scratch_recovery phase=mounted-root-pin desired=0x00000080 share=0x00000003")?;
                                let result = (|| {
                                    ensure!(
                                        access::identity(root.0, true)? == ready.root_id
                                            && access::name(root.0)? == ready.native_root,
                                        "scratch root object was replaced"
                                    );
                                    let (serial, _) = disk::filesystem(&mount.root)?;
                                    ensure!(
                                        serial == ready.serial,
                                        "scratch filesystem serial changed"
                                    );
                                    Ok(())
                                })();
                                access::combine(result, root.close())?;
                            }
                        }
                        super::scratch_lease::recover(state, &intent, &created, mount)?;
                        layout::unmount(&mount.binding, &mount.root)?;
                    } else {
                        no_policy_receipt(state)?;
                        ensure!(ready.is_none(), "scratch readiness lacks mount intent");
                    }
                    Ok(())
                })();
                access::combine(result, raw.close())?;
                // At this point every bound volume handle is closed and every own policy is restored.
                let status = unsafe {
                    DetachVirtualDisk(HANDLE(virtual_disk.0), DETACH_VIRTUAL_DISK_FLAG_NONE, 0)
                };
                ensure!(
                    status.0 == 0,
                    "detach owned scratch VHDX failed winerror={}",
                    status.0
                );
                ensure!(
                    disk::attached_path(virtual_disk.0)?.is_none(),
                    "scratch virtual disk remained attached"
                );
            } else {
                no_policy_receipt(state)?;
                if let Some(mount) = mount {
                    ensure!(
                        layout::mounted(&mount.root)?.is_none(),
                        "detached scratch image still has a drive mapping"
                    );
                }
            }
            Ok(())
        })();
        access::combine(
            result,
            virtual_disk
                .close()
                .context("scratch_recovery phase=provider-close"),
        )?;
        if let Some(detached) = detached {
            ensure!(
                detached.image == id,
                "scratch detached completion identity differs"
            );
        } else {
            // A created record closes the recovery-only creation/result crash window.
            if created_record_absent(state, &host)? {
                access::write_json(state, &host, "scratch-disk.created", &created)?;
            }
            access::write_json(state, &host, "scratch-disk.detached", &created)?;
        }
        disk::require_image(&image_path, image.0, id, &host)?;
        image
            .close()
            .context("scratch_recovery phase=metadata-pin-close after_detach=True")?;
        let mut deletion = Owned::open(&image_path, 0x30080, 3, 0x200000)
            .context("scratch_recovery phase=delete-open desired=0x00030080 share=0x00000003 provider_closed=True metadata_pin_closed=True")?;
        let removed = (|| {
            // Reopening never adopts a replacement, even when its bytes or private policy match.
            crate::windows_security::plain_path(&image_path)?;
            access::require_private(deletion.0, &host)?;
            ensure!(
                access::identity(deletion.0, false)? == id,
                "detached scratch deletion object differs from bound image"
            );
            super::scratch_private::mark_delete(deletion.0)
        })();
        access::combine(removed, deletion.close())
    })();
    access::combine(access::combine(result, image.close()), privilege.close())?;
    ensure!(
        !image_path.try_exists()?,
        "detached scratch image was not removed"
    );
    owner.view.require()
}
fn created_record_absent(state: &Path, host: &str) -> Result<bool> {
    Ok(access::read_record(state, host, "scratch-disk.created")?.is_none())
}
