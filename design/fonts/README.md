# Bundled fonts

Both families are licensed under the SIL Open Font License 1.1. The license texts are in `LICENSE-InterTight.txt` and `LICENSE-IBMPlexMono.txt`.

| File | Family | Weight | Source | Version |
|---|---|---|---|---|
| `inter-tight-latin-400-normal.woff2` | Inter Tight | 400 | `@fontsource/inter-tight` 5.3.0 (npm tarball `files/`) | 5.3.0, published 2026-07-19 |
| `inter-tight-latin-500-normal.woff2` | Inter Tight | 500 | same | same |
| `inter-tight-latin-600-normal.woff2` | Inter Tight | 600 | same | same |
| `inter-tight-latin-700-normal.woff2` | Inter Tight | 700 | same | same |
| `ibm-plex-mono-latin-400-normal.woff2` | IBM Plex Mono | 400 | `@fontsource/ibm-plex-mono` 5.3.0 (npm tarball `files/`) | 5.3.0, published 2026-07-19 |
| `ibm-plex-mono-latin-500-normal.woff2` | IBM Plex Mono | 500 | same | same |

The upstream fonts are Inter Tight (Rasmus Andersson, Google Fonts) and IBM Plex Mono (IBM). Fontsource packages the Google Fonts builds for npm.

SHA-256 of each file:

```
6F32DA94D4F26E98CB6CCD97034D306AA38945322C816F54A93C7D15DC0905B8  inter-tight-latin-400-normal.woff2
6C0019F88D5BC179F2C972998ED8C14E779254566DA9081C5E29F364A0A0AEB6  inter-tight-latin-500-normal.woff2
DB1A039D03ED646EF6A899F9FF92BF2F6FE382A49F1B0992066E85CAF88B5BE9  inter-tight-latin-600-normal.woff2
9C4F02F38678F2628292D66C4F7A1A6A06AF7FFAC4D279359B09074E7D0F1FE0  inter-tight-latin-700-normal.woff2
08949F728DC52D528E69B1667D15C89A5686A4EE9A296FF90983985F99C380F7  ibm-plex-mono-latin-400-normal.woff2
01D285447409C8A588692162439A038B8CBD7871309EE20267B0D2D91C6E8E22  ibm-plex-mono-latin-500-normal.woff2
```

Only the latin subset is bundled. Use `design/fonts.css` to declare the faces; do not reference a CDN.
