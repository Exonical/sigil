use crate::icons::Icon;
use dioxus::prelude::*;

#[component]
pub fn SlotsPage() -> Element {
    rsx! {
        div { class: "empty-state",
            div { class: "empty-icon", Icon { name: "grid", size: 28 } }
            h2 { "Yubico OTP slots" }
            p { "OTP slot configuration is coming in a later release." }
        }
    }
}
