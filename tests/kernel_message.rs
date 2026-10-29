// SPDX-License-Identifier: MIT

#![cfg(target_os = "linux")]

use l2tp::{Cookie, KernelCookie, KernelMessage};
use netlink_packet_core::{Emitable, ParseableParametrized};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};
use netlink_packet_l2tp::{L2tpAttribute, L2tpCmd, L2tpMessage};

fn reply(kind: u16, cookie: &[u8]) -> Vec<u8> {
    let header = GenlHeader {
        cmd: L2tpCmd::SessionGet.into(),
        version: 1,
    };
    let mut bytes = vec![0; header.buffer_len()];
    header.emit(&mut bytes);
    bytes.extend_from_slice(&((4 + cookie.len()) as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(cookie);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

#[test]
fn public_decoder_preserves_both_reported_cookie_attributes() {
    for kind in [15, 16] {
        for len in 0..=9 {
            let bytes: Vec<u8> = (1..=len).collect();
            let wire = reply(kind, &bytes);
            let parsed =
                GenlMessage::<KernelMessage>::parse_with_param(&wire, 1234);
            assert_eq!(parsed.is_ok(), len <= 8);
            if let Ok(parsed) = parsed {
                assert_eq!(parsed.family_id(), 1234);
                assert_eq!(parsed.payload.0.cmd, L2tpCmd::SessionGet);
                let raw = match &parsed.payload.0.attributes[0] {
                    L2tpAttribute::Cookie(bytes) if kind == 15 => bytes,
                    L2tpAttribute::PeerCookie(bytes) if kind == 16 => bytes,
                    other => panic!("unexpected attribute: {other:?}"),
                };
                let cookie = KernelCookie::try_from(raw.as_slice()).unwrap();
                assert_eq!(cookie.as_bytes(), bytes);
                assert_eq!(
                    Cookie::try_from(cookie).is_ok(),
                    matches!(len, 0 | 4 | 8)
                );
            }
        }
        let mut malformed = reply(kind, &[1, 2, 3]);
        // The attribute claims bytes beyond the end of the message.
        malformed[4..6].copy_from_slice(&100u16.to_ne_bytes());
        assert!(
            GenlMessage::<KernelMessage>::parse_with_param(&malformed, 1234)
                .is_err()
        );
    }
}

#[test]
fn emission_and_family_metadata_match_upstream_for_valid_requests() {
    let message = L2tpMessage {
        cmd: L2tpCmd::SessionCreate,
        attributes: vec![L2tpAttribute::cookie(vec![1, 2, 3, 4]).unwrap()],
    };
    let wrapper = KernelMessage(message.clone());
    assert_eq!(KernelMessage::family_name(), L2tpMessage::family_name());
    assert_eq!(wrapper.command(), message.command());
    assert_eq!(wrapper.version(), message.version());
    let mut expected = vec![0; message.buffer_len()];
    message.emit(&mut expected);
    let mut actual = vec![0; wrapper.buffer_len()];
    wrapper.emit(&mut actual);
    assert_eq!(actual, expected);
}
