mod app;
mod auth;
mod dialogs;
mod icons;
mod layout;
mod pages;
mod state;
mod windows;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let (width, height) = window_size();
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new().with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title("Sigil")
                    .with_inner_size(dioxus::desktop::LogicalSize::new(width, height))
                    .with_min_inner_size(dioxus::desktop::LogicalSize::new(720.0, 600.0))
                    .with_position(dioxus::desktop::LogicalPosition::new(80.0, 80.0)),
            ),
        )
        .launch(app::app);
}

fn window_size() -> (f64, f64) {
    #[cfg(debug_assertions)]
    {
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--window-size"
                && let Some((width, height)) = arguments.next().and_then(|size| {
                    let (width, height) = size.split_once('x')?;
                    Some((width.parse::<f64>().ok()?, height.parse::<f64>().ok()?))
                })
            {
                return (width.max(720.0), height.max(600.0));
            }
        }
    }
    (1280.0, 800.0)
}
