//! RFC-0034's file assistant: a confined Wasm agent. It reads the text in its input file, asks the local language model to
//! continue it, and writes the continuation to its output file. It holds three capabilities, each asked for at the console
//! and revocable there, and every use of each is in the audit log: the store records the reads and writes, and the
//! inference service each call to the model. The store records the output as written by this app.
//!
//! The text it reads is untrusted, and so is what the model writes back: neither is ever an instruction to this agent.
//! Whatever the input says, all this agent can do is write some text to its one output file.

wit_bindgen::generate!({
    world: "file-assistant",
    path: "wit",
    generate_all,
});

use crate::lantern::host::{filesystem, inference};

/// How long a continuation it asks for.
const MAX_TOKENS: u32 = 64;
/// The store's block size: a file holds at most this many bytes.
const FILE_MAX: usize = 256;

struct Assistant;

impl Guest for Assistant {
    fn run() -> String {
        let (Some(input), Some(output), Some(model)) = (filesystem::open(0), filesystem::open(1), inference::open(0)) else {
            return String::from("error: access: a capability it needs wasn't granted");
        };
        let text = match input.read() {
            Ok(bytes) if bytes.is_empty() => return String::from("error: the input file is empty: write some text to it first"),
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => return format!("error: reading the input: {}", fs_error(e)),
        };
        let continuation = match model.generate(text.trim_end(), MAX_TOKENS) {
            Ok(words) => words,
            Err(e) => return format!("error: the model: {}", model_error(e)),
        };
        let out = fit(&continuation, FILE_MAX);
        if let Err(e) = output.write(out.as_bytes()) {
            return format!("error: writing the output: {}", fs_error(e));
        }
        format!("ok: wrote {} bytes", out.len())
    }
}

fn fs_error(e: filesystem::ErrorCode) -> &'static str {
    match e {
        filesystem::ErrorCode::Access => "access",
        filesystem::ErrorCode::Invalid => "invalid",
    }
}

fn model_error(e: inference::ErrorCode) -> &'static str {
    match e {
        inference::ErrorCode::Access => "access",
        inference::ErrorCode::Invalid => "invalid",
        inference::ErrorCode::Failed => "failed: no model",
    }
}

/// `text`, cut to at most `max` bytes at a character boundary, and at the last full stop or space before that if it had
/// to be cut.
fn fit(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &text[..end];
    match cut.rfind(". ").map(|i| i + 1).or_else(|| cut.rfind(' ')) {
        Some(i) if i > 0 => &cut[..i],
        _ => cut,
    }
}

export!(Assistant);
