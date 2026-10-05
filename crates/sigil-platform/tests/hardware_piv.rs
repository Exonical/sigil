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
    let mutation_serial = std::env::var("SIGIL_HARDWARE_MUTATION_SERIAL").ok();
    let mut inspected = false;
    for device in devices
        .iter()
        .filter(|device| device.id.0.starts_with("windows-pcsc:"))
        .filter(|device| {
            mutation_serial
                .as_deref()
                .is_none_or(|serial| device.serial.as_deref() == Some(serial))
        })
    {
        inspected = true;
        if let Some(expected_serial) = mutation_serial.as_deref() {
            let checked_serial = discovery
                .piv_serial(&device.id, expected_serial)
                .unwrap_or_else(|error| {
                    panic!(
                        "in-transaction PIV serial check failed for {}: {error:?}",
                        device.id.0
                    )
                });
            assert_eq!(checked_serial, expected_serial);
            println!("piv_serial_check={checked_serial}");
        }
        let info = discovery
            .piv_info(&device.id)
            .unwrap_or_else(|error| panic!("PIV info failed for {}: {error:?}", device.id.0));
        let slots = discovery.piv_slots(&device.id).unwrap_or_else(|error| {
            panic!("PIV slot inspection failed for {}: {error:?}", device.id.0)
        });
        println!(
            "piv_info serial={} fips={:?} pin_remaining={} pin_default={:?} puk_remaining={} puk_default={:?} management_key={} management_key_default={:?}",
            device.serial.as_deref().unwrap_or("unknown"),
            device.fips,
            info.pin
                .as_ref()
                .map(|value| value.remaining)
                .unwrap_or_default(),
            info.pin.as_ref().and_then(|value| value.default_value),
            info.puk
                .as_ref()
                .map(|value| value.remaining)
                .unwrap_or_default(),
            info.puk.as_ref().and_then(|value| value.default_value),
            info.management_key
                .as_ref()
                .map(|value| value.algorithm.to_string())
                .unwrap_or_else(|| "unknown".into()),
            info.management_key
                .as_ref()
                .and_then(|value| value.default_value),
        );
        if mutation_serial.as_deref() == Some("39192733") {
            assert_eq!(device.serial.as_deref(), Some("39192733"));
            assert_eq!(device.fips, Some(true));
            assert_eq!(info.pin.as_ref().map(|value| value.remaining), Some(3));
            assert_eq!(
                info.pin.as_ref().and_then(|value| value.default_value),
                Some(true)
            );
            assert_eq!(info.puk.as_ref().map(|value| value.remaining), Some(3));
            assert_eq!(
                info.puk.as_ref().and_then(|value| value.default_value),
                Some(true)
            );
            assert_eq!(
                info.management_key.as_ref().map(|value| value.algorithm),
                Some(sigil_core::PivAlgorithm::Aes192)
            );
            assert_eq!(
                info.management_key
                    .as_ref()
                    .and_then(|value| value.default_value),
                Some(true)
            );
        }
        println!(
            "piv_slots serial={} {}",
            device.serial.as_deref().unwrap_or("unknown"),
            slots
                .iter()
                .map(|slot| format!(
                    "{}:{:?}:certificate={}",
                    slot.slot,
                    slot.key,
                    slot.certificate.is_some()
                ))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if mutation_serial.as_deref() == Some("39192733") {
            for slot in sigil_core::PivSlot::STANDARD {
                let info = slots
                    .iter()
                    .find(|entry| entry.slot == slot)
                    .expect("standard PIV slot");
                assert_eq!(info.key, sigil_core::KeyStatus::Absent);
                assert!(info.certificate.is_none());
            }
            assert!(
                slots
                    .iter()
                    .find(|entry| entry.slot == sigil_core::PivSlot::ATTESTATION)
                    .is_some_and(|entry| entry.certificate.is_some())
            );
        }
    }
    if mutation_serial.as_deref() == Some("39192733") {
        assert!(
            inspected,
            "authorized serial was not found for final read-only inspection"
        );
    }
}
