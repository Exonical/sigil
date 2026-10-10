//! Timestamp formatting shared by the GUI and the certificate parser.
//!
//! The display rule is ISO-8601 in UTC, to the minute: `2023-11-14 22:13Z`. It is the same rule the portal uses, and
//! it is documented in `design/README.md`.

/// Formats a Unix time (seconds since 1970-01-01T00:00:00Z) as `YYYY-MM-DD HH:MMZ`.
pub fn format_utc_minute(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}Z")
}

/// Converts days since the Unix epoch to a proleptic Gregorian (year, month, day).
/// Howard Hinnant's `civil_from_days` algorithm, chrono-free.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::format_utc_minute;

    #[test]
    fn formats_known_instants_in_utc_to_the_minute() {
        assert_eq!(format_utc_minute(0), "1970-01-01 00:00Z");
        assert_eq!(format_utc_minute(-1), "1969-12-31 23:59Z");
        assert_eq!(format_utc_minute(1_700_000_000), "2023-11-14 22:13Z");
        assert_eq!(format_utc_minute(951_782_400), "2000-02-29 00:00Z");
        assert_eq!(format_utc_minute(1_790_000_000), "2026-09-21 14:13Z");
    }
}
