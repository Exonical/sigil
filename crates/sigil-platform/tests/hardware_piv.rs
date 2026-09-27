#![cfg(target_os = "windows")]

use sigil_core::{DeviceDiscovery, PivInspection};
use sigil_platform::NativeDiscovery;

#[test]
fn read_only_piv_inspection_on_connected_smart_cards() {
    if std::env::var("SIGIL_HARDWARE_TESTS").as_deref() != Ok("1") {
        return;
    }
    let discovery = NativeDiscovery;
    let devices = discovery.list().expect("native device inventory");
    for device in devices
        .iter()
        .filter(|device| device.id.0.starts_with("windows-pcsc:"))
    {
        assert!(
            discovery.piv_info(&device.id).is_ok(),
            "PIV info failed for {}",
            device.id.0
        );
        assert!(
            discovery.piv_slots(&device.id).is_ok(),
            "PIV slot inspection failed for {}",
            device.id.0
        );
    }
}
