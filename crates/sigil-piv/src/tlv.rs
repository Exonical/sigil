use sigil_core::{CredentialError, Result};

/// Parse ordered BER-TLV elements with one- or two-byte tags and short, 0x81,
/// or 0x82 lengths.
pub fn parse(input: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset < input.len() {
        let first = *input
            .get(offset)
            .ok_or_else(|| CredentialError::SmartCardOperation("truncated BER-TLV tag".into()))?;
        offset += 1;
        let tag = if first & 0x1f == 0x1f {
            let second = *input.get(offset).ok_or_else(|| {
                CredentialError::SmartCardOperation("truncated BER-TLV tag".into())
            })?;
            if second & 0x80 != 0 {
                return Err(CredentialError::SmartCardOperation(
                    "unsupported BER-TLV tag width".into(),
                ));
            }
            offset += 1;
            u16::from_be_bytes([first, second])
        } else {
            u16::from(first)
        };
        let first_length = *input.get(offset).ok_or_else(|| {
            CredentialError::SmartCardOperation("truncated BER-TLV length".into())
        })?;
        offset += 1;
        let length = match first_length {
            value @ 0..=0x7f => usize::from(value),
            0x81 => {
                let value = *input.get(offset).ok_or_else(|| {
                    CredentialError::SmartCardOperation("truncated BER-TLV length".into())
                })?;
                offset += 1;
                usize::from(value)
            }
            0x82 => {
                let bytes = input.get(offset..offset + 2).ok_or_else(|| {
                    CredentialError::SmartCardOperation("truncated BER-TLV length".into())
                })?;
                offset += 2;
                usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            _ => {
                return Err(CredentialError::SmartCardOperation(
                    "unsupported BER-TLV length encoding".into(),
                ));
            }
        };
        let end = offset
            .checked_add(length)
            .ok_or_else(|| CredentialError::SmartCardOperation("BER-TLV length overflow".into()))?;
        let value = input
            .get(offset..end)
            .ok_or_else(|| CredentialError::SmartCardOperation("truncated BER-TLV value".into()))?;
        elements.push((tag, value.to_vec()));
        offset = end;
    }
    Ok(elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ordered_tags_and_supported_lengths() {
        let mut bytes = vec![0x53, 0x81, 0x80];
        bytes.extend([0u8; 128]);
        bytes.extend_from_slice(&[0x70, 0x00, 0x7f, 0x01, 0x81, 0x01, 0xaa]);
        let parsed = parse(&bytes).expect("valid TLV");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, 0x53);
        assert_eq!(parsed[0].1.len(), 128);
        assert_eq!(parsed[1], (0x70, Vec::new()));
        assert_eq!(parsed[2], (0x7f01, vec![0xaa]));
        assert!(parse(&[0x53, 0x82, 0x01]).is_err());
        assert!(parse(&[0x53, 0x02, 0x00]).is_err());
    }
}
