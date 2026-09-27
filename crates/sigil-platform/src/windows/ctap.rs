//! Restricted CTAPHID transport for Yubico's read-only device-info command.
//! No generic CTAP command API is exposed to callers.

use std::time::{Duration, Instant};

use hidapi::HidDevice;
use sigil_core::FirmwareVersion;
use sigil_yubikey::management::{self, ManagementInfo, TAG_MORE_DATA, Tags};

use super::MAX_INFO_PAGES;

const BROADCAST_CID: [u8; 4] = [0xff; 4];
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_KEEPALIVE: u8 = 0x3b;
const CTAPHID_READ_CONFIG: u8 = 0x42;
const PACKET_LEN: usize = 64;
const MAX_REPLY_LEN: usize = 1024;
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct HidMetadata {
    pub firmware: Option<FirmwareVersion>,
    pub details: Option<ManagementInfo>,
}

pub(super) fn read_info(device: &HidDevice) -> Option<HidMetadata> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).ok()?;
    let init = exchange(device, BROADCAST_CID, CTAPHID_INIT, &nonce)?;
    let (cid, firmware) = parse_init(&init, &nonce)?;
    let mut tags = Tags::new();
    let mut details = None;
    for page in 0..MAX_INFO_PAGES {
        let Some(encoded) = exchange(device, cid, CTAPHID_READ_CONFIG, &[page]) else {
            break;
        };
        let Ok(mut page_tags) = management::parse_page(&encoded) else {
            break;
        };
        let more = page_tags
            .remove(&TAG_MORE_DATA)
            .is_some_and(|value| value.iter().any(|byte| *byte != 0));
        tags.append(&mut page_tags);
        if !more {
            details = ManagementInfo::from_tags(&tags, firmware.clone()).ok();
            break;
        }
    }
    Some(HidMetadata { firmware, details })
}

fn parse_init(init: &[u8], nonce: &[u8; 8]) -> Option<([u8; 4], Option<FirmwareVersion>)> {
    if init.len() < 17 || init[..8] != *nonce {
        return None;
    }
    let cid: [u8; 4] = init[8..12].try_into().ok()?;
    if cid == [0; 4] || cid == BROADCAST_CID {
        return None;
    }
    // The device version field is vendor defined. For YubiKeys 4 and newer,
    // Yubico reports the firmware version here; do not guess on older keys.
    let firmware = (init[13] >= 4).then_some(FirmwareVersion {
        major: init[13],
        minor: init[14],
        patch: init[15],
    });

    Some((cid, firmware))
}

fn exchange(device: &HidDevice, cid: [u8; 4], command: u8, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_REPLY_LEN {
        return None;
    }
    let mut packet = [0u8; PACKET_LEN + 1]; // leading HID report ID 0
    packet[1..5].copy_from_slice(&cid);
    packet[5] = command | 0x80;
    packet[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first_len = payload.len().min(PACKET_LEN - 7);
    packet[8..8 + first_len].copy_from_slice(&payload[..first_len]);
    device.write(&packet).ok()?;

    let mut offset = first_len;
    let mut sequence = 0u8;
    while offset < payload.len() {
        let mut continuation = [0u8; PACKET_LEN + 1];
        continuation[1..5].copy_from_slice(&cid);
        continuation[5] = sequence;
        let len = (payload.len() - offset).min(PACKET_LEN - 5);
        continuation[6..6 + len].copy_from_slice(&payload[offset..offset + len]);
        device.write(&continuation).ok()?;
        offset += len;
        sequence = sequence.checked_add(1)?;
    }

    read_response(cid, command, |buffer, timeout| {
        device.read_timeout(buffer, timeout).ok()
    })
}

fn read_response(
    cid: [u8; 4],
    command: u8,
    mut read_packet: impl FnMut(&mut [u8; PACKET_LEN], i32) -> Option<usize>,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    let mut reply = Vec::new();
    let mut expected_len: Option<usize> = None;
    let mut next_sequence = 0u8;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let mut buffer = [0u8; PACKET_LEN];
        let read = read_packet(&mut buffer, remaining.as_millis().min(1000) as i32)?;
        if read > PACKET_LEN {
            return None;
        }
        if read < 5 || buffer[..4] != cid {
            continue;
        }
        if let Some(total) = expected_len {
            if buffer[4] != next_sequence {
                return None;
            }
            next_sequence = next_sequence.checked_add(1)?;
            let take = (total - reply.len()).min(read - 5);
            reply.extend_from_slice(&buffer[5..5 + take]);
            if reply.len() == total {
                return Some(reply);
            }
        } else {
            if read < 7 {
                continue;
            }
            if buffer[4] == (CTAPHID_KEEPALIVE | 0x80) {
                continue;
            }
            if buffer[4] != (command | 0x80) {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([buffer[5], buffer[6]]));
            if total > MAX_REPLY_LEN {
                return None;
            }
            let take = total.min(read - 7);
            reply.extend_from_slice(&buffer[7..7 + take]);
            if reply.len() == total {
                return Some(reply);
            }
            expected_len = Some(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_requires_matching_nonce_and_valid_channel() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut response = [0u8; 17];
        response[..8].copy_from_slice(&nonce);
        response[8..12].copy_from_slice(&[0, 0, 0, 1]);
        response[13..16].copy_from_slice(&[4, 3, 7]);
        let (cid, firmware) = parse_init(&response, &nonce).expect("valid CTAPHID_INIT");
        assert_eq!(cid, [0, 0, 0, 1]);
        assert_eq!(firmware.unwrap().major, 4);
        assert!(parse_init(&response, &[0; 8]).is_none());
        response[8..12].fill(0xff);
        assert!(parse_init(&response, &nonce).is_none());
    }

    #[test]
    fn response_reassembles_packets_and_ignores_keepalive() {
        let cid = [1, 2, 3, 4];
        let mut keepalive = [0u8; PACKET_LEN];
        keepalive[..4].copy_from_slice(&cid);
        keepalive[4] = CTAPHID_KEEPALIVE | 0x80;
        let mut first = [0u8; PACKET_LEN];
        first[..4].copy_from_slice(&cid);
        first[4] = CTAPHID_READ_CONFIG | 0x80;
        first[5..7].copy_from_slice(&70u16.to_be_bytes());
        first[7..64].fill(0xa5);
        let mut next = [0u8; PACKET_LEN];
        next[..4].copy_from_slice(&cid);
        next[4] = 0;
        next[5..18].fill(0x5a);
        let mut packets = [keepalive, first, next].into_iter();
        let result = read_response(cid, CTAPHID_READ_CONFIG, |buffer, _| {
            *buffer = packets.next()?;
            Some(PACKET_LEN)
        })
        .expect("complete response");
        assert_eq!(result.len(), 70);
        assert_eq!(result[0], 0xa5);
        assert_eq!(result[69], 0x5a);
    }

    #[test]
    fn response_rejects_wrong_sequence() {
        let cid = [1, 2, 3, 4];
        let mut first = [0u8; PACKET_LEN];
        first[..4].copy_from_slice(&cid);
        first[4] = CTAPHID_READ_CONFIG | 0x80;
        first[5..7].copy_from_slice(&70u16.to_be_bytes());
        let mut next = [0u8; PACKET_LEN];
        next[..4].copy_from_slice(&cid);
        next[4] = 1;
        let mut packets = [first, next].into_iter();
        assert!(
            read_response(cid, CTAPHID_READ_CONFIG, |buffer, _| {
                *buffer = packets.next()?;
                Some(PACKET_LEN)
            })
            .is_none()
        );
    }
}
