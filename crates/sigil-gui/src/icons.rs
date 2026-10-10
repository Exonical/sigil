// Inline Lucide SVG paths, licensed under ISC:
// https://github.com/lucide-icons/lucide/blob/main/LICENSE.

use dioxus::prelude::*;

#[component]
pub fn Icon(name: &'static str, #[props(default = 18)] size: u8) -> Element {
    let drawing = match name {
        "menu" => rsx! {
            path { d: "M4 6h16M4 12h16M4 18h16" }
        },
        "home" => rsx! {
            path { d: "m3 10 9-7 9 7" }
            path { d: "M5 9v12h14V9" }
            path { d: "M9 21v-7h6v7" }
        },
        "users" => rsx! {
            path { d: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" }
            circle { cx: "9", cy: "7", r: "4" }
            path { d: "M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" }
        },
        "key" => rsx! {
            circle { cx: "8", cy: "15", r: "5" }
            path { d: "m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3" }
        },
        "certificate" => rsx! {
            path { d: "M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3" }
            path { d: "M8 3v4h4" }
            path { d: "M8 13h8M8 17h5" }
            circle { cx: "17", cy: "7", r: "4" }
            path { d: "m15.5 10.5-1 5 2.5-1.5 2.5 1.5-1-5" }
        },
        "grid" => rsx! {
            rect { x: "3", y: "3", width: "8", height: "8", rx: "1" }
            rect { x: "13", y: "3", width: "8", height: "8", rx: "1" }
            rect { x: "3", y: "13", width: "8", height: "8", rx: "1" }
            rect { x: "13", y: "13", width: "8", height: "8", rx: "1" }
        },
        "settings" => rsx! {
            path { d: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z" }
            path { d: "m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.6.9l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.6-.9l-1.7.6-1.4-2.4 1.4-1.1a8 8 0 0 1 0-1.9l-1.4-1.1 1.4-2.4 1.7.6a8 8 0 0 1 1.6-.9l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.6.9l1.7-.6 1.4 2.4-1.4 1.1a8 8 0 0 1 0 1.9Z" }
        },
        "chevron-down" => rsx! { path { d: "m6 9 6 6 6-6" } },
        "chevron-left" => rsx! { path { d: "m15 18-6-6 6-6" } },
        "chevron-right" => rsx! { path { d: "m9 18 6-6-6-6" } },
        "panel" => rsx! {
            rect { x: "3", y: "4", width: "18", height: "16", rx: "2" }
            path { d: "M15 4v16" }
        },
        "refresh" => rsx! {
            path { d: "M20 7v5h-5M4 17v-5h5" }
            path { d: "M5.6 9a7 7 0 0 1 11.6-2L20 12M4 12l2.8 5a7 7 0 0 0 11.6-2" }
        },
        "warning" => rsx! {
            path { d: "m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z" }
            path { d: "M12 9v4M12 17h.01" }
        },
        "shield" => rsx! {
            path { d: "M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" }
            path { d: "m9 12 2 2 4-4" }
        },
        "lock" => rsx! {
            rect { x: "4", y: "10", width: "16", height: "11", rx: "2" }
            path { d: "M8 10V7a4 4 0 1 1 8 0v3M12 14v3" }
        },
        "copy" => rsx! {
            rect { x: "8", y: "8", width: "13", height: "13", rx: "2" }
            path { d: "M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" }
        },
        "plus" => rsx! { path { d: "M12 5v14M5 12h14" } },
        "trash" => rsx! {
            path { d: "M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5" }
        },
        "download" => rsx! {
            path { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }
            path { d: "m7 10 5 5 5-5M12 15V3" }
        },
        "upload" => rsx! {
            path { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }
            path { d: "m17 8-5-5-5 5M12 3v12" }
        },
        "rotate" => rsx! {
            path { d: "M3 12a9 9 0 1 0 3-6.7L3 8" }
            path { d: "M3 3v5h5" }
            path { d: "M12 7v5l3 2" }
        },
        "check" => rsx! { path { d: "m5 12 4 4L19 6" } },
        "fingerprint" => rsx! {
            path { d: "M12 11a2 2 0 0 0-2 2c0 2.5-.5 4.5-1.5 6" }
            path { d: "M14 13c0 3-.4 5.3-1.2 7" }
            path { d: "M7.7 17.5c-.7-1.1-1.2-2.8-1.2-4.5a5.5 5.5 0 0 1 11 0c0 2-.2 3.8-.7 5.5" }
            path { d: "M5 12a7 7 0 0 1 14 0M12 3a9 9 0 0 1 9 9" }
        },
        "x" => rsx! { path { d: "m18 6-12 12M6 6l12 12" } },
        "info" => rsx! {
            circle { cx: "12", cy: "12", r: "10" }
            path { d: "M12 16v-4M12 8h.01" }
        },
        _ => rsx! {
            circle { cx: "12", cy: "12", r: "9" }
        },
    };

    rsx! {
        svg {
            class: "icon",
            width: "{size}",
            height: "{size}",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "1.8",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            {drawing}
        }
    }
}
