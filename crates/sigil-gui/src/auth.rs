//! Sign-in state for the GUI. All identity-provider work runs on background threads so the window
//! never blocks; the UI only reads `AuthStatus` and the shared session handle.

use std::{
    sync::{Arc, atomic::Ordering},
    thread,
    time::Duration,
};

use dioxus::prelude::*;
use sigil_auth::{AuthError, OidcSettings, Session, platform_store};

use crate::{icons::Icon, state::AppState};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthConfig {
    NotConfigured,
    Invalid(String),
    Configured(OidcSettings),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthStatus {
    Checking,
    SignedOut,
    Waiting,
    SignedIn(String),
    Error(String),
}

pub fn load_config() -> AuthConfig {
    match sigil_auth::load_settings() {
        Ok(Some(settings)) => AuthConfig::Configured(settings),
        Ok(None) => AuthConfig::NotConfigured,
        Err(error) => AuthConfig::Invalid(error.to_string()),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, AuthError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| AuthError::Config(error.to_string()))
}

fn publish<T: Send + Sync + 'static>(signal: &mut SyncSignal<T>, value: T) {
    if let Ok(mut current) = signal.try_write() {
        *current = value;
    }
}

/// Silently restores a previous sign-in in the background.
pub fn restore(state: &AppState) {
    let AuthConfig::Configured(settings) = state.auth_config.clone() else {
        return;
    };
    let mut status = state.auth;
    let mut session = state.session;
    thread::spawn(move || {
        let outcome = runtime().and_then(|runtime| {
            runtime.block_on(Session::load_or_none(&settings, platform_store()))
        });
        match outcome {
            Ok(Some(found)) => {
                let name = found.identity().username;
                publish(&mut session, Some(Arc::new(found)));
                publish(&mut status, AuthStatus::SignedIn(name));
            }
            Ok(None) => publish(&mut status, AuthStatus::SignedOut),
            Err(error) => {
                tracing::warn!(%error, "silent sign-in restore failed");
                publish(&mut status, AuthStatus::SignedOut);
            }
        }
    });
}

/// Starts the interactive sign-in. Cancel with [`cancel_sign_in`].
pub fn sign_in(state: &AppState) {
    let AuthConfig::Configured(settings) = state.auth_config.clone() else {
        return;
    };
    let cancel = Arc::clone(&state.auth_cancel);
    cancel.store(false, Ordering::SeqCst);
    let mut status = state.auth;
    let mut session = state.session;
    publish(&mut status, AuthStatus::Waiting);
    thread::spawn(move || {
        let cancelled = {
            let cancel = Arc::clone(&cancel);
            async move {
                while !cancel.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };
        let outcome = runtime().and_then(|runtime| {
            runtime.block_on(Session::sign_in(
                &settings,
                platform_store(),
                |url| {
                    if let Err(error) = sigil_auth::open_in_browser(url) {
                        tracing::warn!(%error, "could not open the sign-in page");
                    }
                },
                cancelled,
            ))
        });
        match outcome {
            Ok(signed_in) => {
                let name = signed_in.identity().username;
                publish(&mut session, Some(Arc::new(signed_in)));
                publish(&mut status, AuthStatus::SignedIn(name));
            }
            Err(AuthError::Cancelled) => publish(&mut status, AuthStatus::SignedOut),
            Err(error) => publish(&mut status, AuthStatus::Error(error.to_string())),
        }
    });
}

pub fn cancel_sign_in(state: &AppState) {
    state.auth_cancel.store(true, Ordering::SeqCst);
}

pub fn sign_out_clicked(state: &AppState) {
    let AuthConfig::Configured(settings) = state.auth_config.clone() else {
        return;
    };
    let mut status = state.auth;
    let mut session = state.session;
    thread::spawn(move || {
        let outcome = runtime().and_then(|runtime| {
            runtime.block_on(sigil_auth::sign_out(&settings, platform_store()))
        });
        publish(&mut session, None);
        match outcome {
            Ok(()) => publish(&mut status, AuthStatus::SignedOut),
            Err(error) => publish(&mut status, AuthStatus::Error(error.to_string())),
        }
    });
}

/// Sign-in control at the bottom of the left navigation. Hidden when machine policy does not configure sign-in.
#[component]
pub fn AuthArea() -> Element {
    let state = use_context::<AppState>();
    let mut menu_open = use_signal(|| false);
    let status = state.auth.read().clone();

    match state.auth_config.clone() {
        AuthConfig::NotConfigured => rsx! {},
        AuthConfig::Invalid(_) => rsx! {
            button {
                class: "nav-item auth-button",
                disabled: true,
                title: "Sign-in is not configured",
                Icon { name: "users", size: 19 }
                span { class: "nav-label", "Sign in" }
            }
        },
        AuthConfig::Configured(_) => match status {
            AuthStatus::Checking => rsx! {
                button { class: "nav-item auth-button", disabled: true,
                    Icon { name: "users", size: 19 }
                    span { class: "nav-label", "Checking sign-in…" }
                }
            },
            AuthStatus::Waiting => rsx! {
                button { class: "nav-item auth-button", disabled: true,
                    Icon { name: "users", size: 19 }
                    span { class: "nav-label", "Waiting for browser…" }
                }
                button {
                    class: "nav-item auth-cancel",
                    onclick: {
                        let state = state.clone();
                        move |_| cancel_sign_in(&state)
                    },
                    Icon { name: "x", size: 16 }
                    span { class: "nav-label", "Cancel" }
                }
            },
            AuthStatus::SignedIn(name) => rsx! {
                button {
                    class: "nav-item auth-button",
                    aria_expanded: menu_open().to_string(),
                    title: "{name}",
                    onclick: move |_| menu_open.set(!menu_open()),
                    Icon { name: "users", size: 19 }
                    span { class: "nav-label", "{name}" }
                }
                if menu_open() {
                    button {
                        class: "nav-item auth-menu",
                        onclick: {
                            let state = state.clone();
                            move |_| {
                                menu_open.set(false);
                                sign_out_clicked(&state);
                            }
                        },
                        Icon { name: "x", size: 16 }
                        span { class: "nav-label", "Sign out" }
                    }
                }
            },
            AuthStatus::SignedOut => rsx! {
                button {
                    class: "nav-item auth-button",
                    onclick: {
                        let state = state.clone();
                        move |_| sign_in(&state)
                    },
                    Icon { name: "users", size: 19 }
                    span { class: "nav-label", "Sign in" }
                }
            },
            AuthStatus::Error(message) => rsx! {
                button {
                    class: "nav-item auth-button",
                    title: "{message}",
                    onclick: {
                        let state = state.clone();
                        move |_| sign_in(&state)
                    },
                    Icon { name: "warning", size: 19 }
                    span { class: "nav-label", "Sign in again" }
                }
            },
        },
    }
}
