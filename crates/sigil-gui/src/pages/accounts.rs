use crate::icons::Icon;
use dioxus::prelude::*;

#[component]
pub fn AccountsPage() -> Element {
    rsx! {
        div { class: "empty-state",
            div { class: "empty-icon", Icon { name: "users", size: 28 } }
            h2 { "OATH accounts" }
            p { "OATH accounts are coming in a later release." }
        }
    }
}
