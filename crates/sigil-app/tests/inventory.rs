use std::sync::Arc;
use std::time::Duration;

use sigil_app::CredentialService;
use sigil_core::{CredentialError, DeviceDiscovery, DeviceEvent, DeviceId};
use sigil_mock::MockDiscovery;

#[test]
fn empty_inventory_and_missing_selection() {
    let service = CredentialService::new(Arc::new(MockDiscovery::default()));
    assert!(service.devices().expect("inventory").is_empty());
    assert_eq!(
        service.device(&DeviceId("missing".into())),
        Err(CredentialError::DeviceNotFound("missing".into()))
    );
}

#[test]
fn multiple_devices_are_selected_by_opaque_id() {
    let example = MockDiscovery::with_example()
        .list()
        .expect("fixture")
        .remove(0);
    let mut second = example.clone();
    second.id = DeviceId("mock-other".into());
    second.serial = Some("87654321".into());
    let service =
        CredentialService::new(Arc::new(MockDiscovery::with_devices(vec![second, example])));
    assert_eq!(service.devices().expect("inventory").len(), 2);
    assert_eq!(
        service
            .device(&DeviceId("mock-other".into()))
            .expect("selected")
            .serial
            .as_deref(),
        Some("87654321")
    );
}

#[test]
fn insertion_update_and_removal_emit_events() {
    let mock = Arc::new(MockDiscovery::default());
    let service = CredentialService::new(mock.clone());
    let events = service.watch_devices().expect("subscribe");
    let device = MockDiscovery::with_example()
        .list()
        .expect("fixture")
        .remove(0);
    mock.connect(device.clone()).expect("connect");
    assert_eq!(
        events
            .recv_timeout(Duration::from_millis(100))
            .expect("connected"),
        DeviceEvent::Connected(device.clone())
    );
    mock.connect(device.clone()).expect("update");
    assert_eq!(
        events
            .recv_timeout(Duration::from_millis(100))
            .expect("updated"),
        DeviceEvent::Updated(device.clone())
    );
    mock.disconnect(&device.id).expect("disconnect");
    assert_eq!(
        events
            .recv_timeout(Duration::from_millis(100))
            .expect("disconnected"),
        DeviceEvent::Disconnected(device.id.clone())
    );
    assert_eq!(
        service.device(&device.id),
        Err(CredentialError::DeviceNotFound(device.id.0))
    );
}
