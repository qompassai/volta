//! crates/volta-cli/src/bin/volta_delete.rs - volta-delete binary.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! `volta-delete [--all] [--all-bindings] <base> <query>` (SPEC
//! 15.2). Help and version work with no state present (CLI-1);
//! failures are one structured line on stderr, exit 2 (CLI-2).

#![forbid(unsafe_code)]

use clap::Parser;
use volta_core::store::Store;

#[path = "../delete.rs"]
mod delete;

/// volta-delete: remove a binding or a certificate from a store.
#[derive(Parser)]
#[command(name = "volta-delete", version, about)]
struct Args {
    /// Delete all bindings AND the key.
    #[arg(long)]
    all: bool,
    /// Delete all bindings for the queried key.
    #[arg(long)]
    all_bindings: bool,
    /// The store base directory (the server's data_dir).
    base: String,
    /// Email address, fingerprint, or KeyID.
    query: String,
}

fn main() {
    let args = Args::parse();
    let outcome = (|| -> Result<serde_json::Value, volta_core::error::VoltaError> {
        let mut store = Store::open(std::path::Path::new(&args.base))?;
        delete::delete(&mut store, &args.query, args.all, args.all_bindings)
    })();
    match outcome {
        Ok(report) => {
            println!("{report}");
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"code": error.code(), "detail": error.to_string()})
            );
            std::process::exit(2);
        }
    }
}
