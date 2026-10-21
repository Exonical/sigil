use anyhow::{Context, Result, anyhow};
use serde_json::json;
use sigil_auth::{Identity, OidcSettings, Session, load_settings, platform_store, sign_out};
use zeroize::Zeroizing;

/// Commands that sign in with the identity provider. They never touch hardware.
pub fn is_auth_command(command: &crate::Command) -> bool {
    matches!(
        command,
        crate::Command::Login | crate::Command::Logout | crate::Command::Whoami
    )
}

pub fn handle(command: &crate::Command, json: bool) -> Result<String> {
    match command {
        crate::Command::Login => login(json),
        crate::Command::Logout => logout(),
        crate::Command::Whoami => whoami(json),
        _ => Err(anyhow!("not a sign-in command")),
    }
}

fn settings() -> Result<OidcSettings> {
    load_settings()?.ok_or_else(|| anyhow!("sign-in is not configured by machine policy"))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not start the sign-in runtime")
}

fn login(json: bool) -> Result<String> {
    let settings = settings()?;
    let runtime = runtime()?;
    let session = runtime.block_on(Session::sign_in(
        &settings,
        platform_store(),
        |url| {
            eprintln!("Opening your browser to sign in. If it does not open, visit:\n{url}");
            if let Err(error) = sigil_auth::open_in_browser(url) {
                eprintln!("{error}");
            }
        },
        std::future::pending::<()>(),
    ))?;
    let expires_at = runtime.block_on(session.access_expires_at());
    Ok(render_identity(
        &session.identity(),
        expires_at,
        json,
        "Signed in as",
    ))
}

fn logout() -> Result<String> {
    let settings = settings()?;
    runtime()?.block_on(sign_out(&settings, platform_store()))?;
    Ok("Signed out.".into())
}

fn whoami(json: bool) -> Result<String> {
    let settings = settings()?;
    let runtime = runtime()?;
    match runtime.block_on(Session::load_or_none(&settings, platform_store()))? {
        None => Ok(if json {
            serde_json::to_string_pretty(&json!({ "signed_in": false }))?
        } else {
            "not signed in".into()
        }),
        Some(session) => {
            let expires_at = runtime.block_on(session.access_expires_at());
            Ok(render_identity(
                &session.identity(),
                expires_at,
                json,
                "Signed in as",
            ))
        }
    }
}

fn render_identity(identity: &Identity, expires_at: i64, json: bool, heading: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    if json {
        return serde_json::to_string_pretty(&json!({
            "signed_in": true,
            "username": identity.username,
            "subject": identity.subject,
            "email": identity.email,
            "groups": identity.groups,
            "access_token_expires_at": expires_at,
        }))
        .unwrap_or_default();
    }
    let groups = if identity.groups.is_empty() {
        "none".to_owned()
    } else {
        identity.groups.join(", ")
    };
    format!(
        "{heading} {}\nEmail: {}\nGroups: {groups}\nAccess token expires in {} s",
        identity.username,
        identity.email.as_deref().unwrap_or("unknown"),
        (expires_at - now).max(0),
    )
}

/// Returns a current access token for a managed agent operation.
pub fn managed_access_token() -> Result<Zeroizing<String>> {
    let settings = settings()?;
    let runtime = runtime()?;
    let session = runtime
        .block_on(Session::load_or_none(&settings, platform_store()))?
        .ok_or_else(|| anyhow!("not signed in; run `cms login`"))?;
    Ok(runtime.block_on(session.access_token())?)
}
