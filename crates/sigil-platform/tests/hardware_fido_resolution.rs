#![cfg(target_os = "windows")]

use sigil_core::{Application, DeviceDiscovery, Transport};
use sigil_platform::NativeDiscovery;

#[test]
fn read_only_fido_hid_resolution_matches_each_usb_pcsc_yubikey_parent() {
    if std::env::var("SIGIL_HARDWARE_TESTS").as_deref() != Ok("1") {
        return;
    }
    let discovery = NativeDiscovery;
    let devices = discovery.list().expect("native device inventory");
    let candidates: Vec<_> = devices
        .iter()
        .filter(|device| {
            device.id.0.starts_with("windows-pcsc:")
                && device.connection == Some(Transport::UsbSmartCard)
                && device.supported_applications.contains(&Application::Fido2)
        })
        .collect();
    assert!(
        !candidates.is_empty(),
        "no PC/SC USB YubiKey with supported FIDO2 was discovered"
    );

    for device in candidates {
        let resolution = discovery
            .resolve_fido_hid_for_device(&device.id)
            .unwrap_or_else(|error| {
                panic!("FIDO HID resolution failed for {}: {error}", device.id.0)
            })
            .unwrap_or_else(|| {
                panic!(
                    "no matching FIDO HID interface was found for {}",
                    device.id.0
                )
            });
        assert_eq!(
            resolution.reader_composite_id.to_ascii_lowercase(),
            resolution.hid_composite_id.to_ascii_lowercase(),
            "resolved interfaces do not share a physical USB parent"
        );
        let usb_identity = resolution
            .reader_composite_id
            .to_ascii_lowercase()
            .split('\\')
            .nth(1)
            .expect("USB VID/PID component")
            .to_owned();
        assert!(usb_identity.starts_with("vid_1050&pid_"));
        assert!(
            resolution
                .hid_path
                .to_ascii_lowercase()
                .contains(&usb_identity)
        );
        println!(
            "Resolved {} to {} (USB parent {})",
            device.id.0, resolution.hid_path, resolution.reader_composite_id
        );
    }
}
