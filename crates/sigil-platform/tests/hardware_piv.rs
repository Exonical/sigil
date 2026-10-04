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
        discovery
            .piv_info(&device.id)
            .unwrap_or_else(|error| panic!("PIV info failed for {}: {error:?}", device.id.0));
        let slots = discovery.piv_slots(&device.id).unwrap_or_else(|error| {
            panic!("PIV slot inspection failed for {}: {error:?}", device.id.0)
        });
        println!(
            "Read PIV info and {} slots from {}",
            slots.len(),
            device.id.0
        );
    }
}
