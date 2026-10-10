mod factory_reset;
mod piv;
mod toggle_applications;

use dioxus::prelude::*;

use crate::state::{AppState, DialogKind};

#[component]
pub fn DialogHost() -> Element {
    let state = use_context::<AppState>();
    let dialog = *state.dialog.read();
    let device = state.current_device();
    match (dialog, device) {
        (Some(DialogKind::ToggleApplications), Some(device)) => {
            rsx! { toggle_applications::ToggleApplicationsDialog { device } }
        }
        (Some(DialogKind::FactoryReset), Some(device)) => {
            rsx! { factory_reset::FactoryResetDialog { device } }
        }
        (Some(DialogKind::SetupFips), Some(device)) => {
            rsx! { piv::FipsSetupDialog { device } }
        }
        (Some(DialogKind::Piv(action)), Some(device)) => {
            rsx! { piv::PivDialog { device, action } }
        }
        _ => rsx! {},
    }
}
