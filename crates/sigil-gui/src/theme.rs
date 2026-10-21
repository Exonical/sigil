//! The GUI stylesheet: the shared design tokens and bundled fonts from `design/`, then the GUI rules.
//!
//! `design/fonts.css` refers to its fonts by relative URL. Those files are embedded here as data URLs, so the window
//! renders offline and the shared declarations stay the single source of truth.

const TOKENS: &str = include_str!("../../../design/tokens.css");
const FONTS: &str = include_str!("../../../design/fonts.css");
const RULES: &str = include_str!("theme.css");
const FONT_URL_PREFIX: &str = "./fonts/";

const FONT_FILES: [(&str, &[u8]); 6] = [
    (
        "inter-tight-latin-400-normal.woff2",
        include_bytes!("../../../design/fonts/inter-tight-latin-400-normal.woff2"),
    ),
    (
        "inter-tight-latin-500-normal.woff2",
        include_bytes!("../../../design/fonts/inter-tight-latin-500-normal.woff2"),
    ),
    (
        "inter-tight-latin-600-normal.woff2",
        include_bytes!("../../../design/fonts/inter-tight-latin-600-normal.woff2"),
    ),
    (
        "inter-tight-latin-700-normal.woff2",
        include_bytes!("../../../design/fonts/inter-tight-latin-700-normal.woff2"),
    ),
    (
        "ibm-plex-mono-latin-400-normal.woff2",
        include_bytes!("../../../design/fonts/ibm-plex-mono-latin-400-normal.woff2"),
    ),
    (
        "ibm-plex-mono-latin-500-normal.woff2",
        include_bytes!("../../../design/fonts/ibm-plex-mono-latin-500-normal.woff2"),
    ),
];

/// The complete stylesheet for the window.
pub fn stylesheet() -> String {
    let mut css = String::with_capacity(TOKENS.len() + FONTS.len() * 4 + RULES.len());
    css.push_str(TOKENS);
    css.push('\n');
    css.push_str(&embed_fonts(FONTS));
    css.push('\n');
    css.push_str(RULES);
    css
}

/// Replaces each `./fonts/<file>` URL with a data URL for the embedded file.
fn embed_fonts(css: &str) -> String {
    let mut out = String::with_capacity(css.len() * 4);
    let mut rest = css;
    while let Some(index) = rest.find(FONT_URL_PREFIX) {
        out.push_str(&rest[..index]);
        let after = &rest[index + FONT_URL_PREFIX.len()..];
        let end = after.find('"').unwrap_or(after.len());
        let name = &after[..end];
        out.push_str("data:font/woff2;base64,");
        out.push_str(&base64(font_bytes(name)));
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn font_bytes(name: &str) -> &'static [u8] {
    FONT_FILES
        .iter()
        .find(|(file, _)| *file == name)
        .map(|(_, bytes)| *bytes)
        .unwrap_or(&[])
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - 6 * index;
                out.push(char::from(ALPHABET[((value >> shift) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"Man"), "TWFu");
    }

    #[test]
    fn every_font_url_in_the_shared_declarations_is_bundled() {
        let mut count = 0;
        for part in FONTS.split(FONT_URL_PREFIX).skip(1) {
            let name = &part[..part.find('"').expect("url is quoted")];
            assert!(
                FONT_FILES.iter().any(|(file, _)| *file == name),
                "{name} is not bundled"
            );
            count += 1;
        }
        assert_eq!(count, FONT_FILES.len());
    }

    #[test]
    fn the_stylesheet_has_no_unresolved_font_urls() {
        let css = stylesheet();
        assert!(!css.contains(FONT_URL_PREFIX));
        assert!(css.contains("data:font/woff2;base64,"));
        assert!(css.contains("--sg-bg: #0a0b0c;"));
    }
}
