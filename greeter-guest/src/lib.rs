//! RFC-0035's greeter: a confined Wasm app that says hello to two peers, alice.test and bob.test, through the wallet.
//!
//! It never sees a key, an address or a socket: each peer is a `context` handle the person allowed, and the wallet
//! presents the app's pairwise identity for that peer over an encrypted session. Each peer sees a different identity,
//! and neither can link it to the other's.

wit_bindgen::generate!({
    world: "greeter",
    path: "wit",
    generate_all,
});

use crate::lantern::host::identity;

const PEERS: [&str; 2] = ["alice", "bob"];

struct Greeter;

impl Guest for Greeter {
    fn run() -> String {
        let mut report = String::new();
        let mut greeted = 0;
        for (slot, name) in PEERS.iter().enumerate() {
            let Some(peer) = identity::open(slot as u32) else {
                report.push_str(&format!(" {name}: not granted;"));
                continue;
            };
            let answer = peer
                .connect()
                .and_then(|()| peer.send(b"hello from greeter"))
                .and_then(|()| peer.recv());
            match answer {
                Ok(bytes) => {
                    let text: String = String::from_utf8_lossy(&bytes).chars().filter(|c| !c.is_control()).take(80).collect();
                    report.push_str(&format!(" {name} said {text:?};"));
                    greeted += 1;
                }
                Err(e) => return format!("error: {name}: {}", error(e)),
            }
        }
        if greeted == 0 {
            return format!("error: access: no peer was granted;{report}");
        }
        format!("ok:{report}")
    }
}

fn error(e: identity::ErrorCode) -> &'static str {
    match e {
        identity::ErrorCode::Access => "access",
        identity::ErrorCode::Unreachable => "unreachable",
        identity::ErrorCode::Refused => "refused",
        identity::ErrorCode::Invalid => "invalid",
    }
}

export!(Greeter);
