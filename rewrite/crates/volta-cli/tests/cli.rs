//! crates/volta-cli/tests/cli.rs - voltactl / volta-delete behavior.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! CLI-1 (help/version need no configuration), CLI-2 (missing
//! configuration is one structured stderr line, exit 2), the
//! local import/stats/delete flow, and the stdio MCP transport.

use std::io::Write;
use std::process::{Command, Stdio};

const ALICE: &str = include_str!("../../../tests/fixtures/alice.asc");
const ALICE_FPR: &str = "B75FDD3A562A4951988BA325BAA8C11D29B6FDC9";

fn tempdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("voltactl-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    std::fs::write(dir.join("token-secret"), [7u8; 32]).expect("secret");
    let config = format!(
        "base_uri = \"https://localhost:8737\"\n\
         data_dir = \"{dir}\"\n\
         origin = \"https://localhost:8737\"\n\
         rp_id = \"localhost\"\n\
         token_secret_ref = \"file:{dir}/token-secret\"\n",
        dir = dir.display(),
    );
    let path = dir.join("volta.toml");
    std::fs::write(&path, config).expect("config");
    path
}

#[test]
fn help_and_version_need_no_config() {
    let dir = tempdir("help");
    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .arg("--help")
        .current_dir(&dir)
        .output()
        .expect("run");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Operator"));
    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .arg("--version")
        .current_dir(&dir)
        .output()
        .expect("run");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("2.0.0"));
    let output = Command::new(env!("CARGO_BIN_EXE_volta-delete"))
        .arg("--help")
        .current_dir(&dir)
        .output()
        .expect("run");
    assert!(output.status.success());
}

#[test]
fn missing_config_is_structured_exit_2() {
    let dir = tempdir("noconfig");
    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .args(["stats"])
        .current_dir(&dir)
        .env_remove("VOLTA_CONFIG")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("E_CONFIG_INVALID"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "one structured line: {stderr}");
}

#[test]
fn import_stats_delete_flow() {
    let dir = tempdir("flow");
    let config = write_config(&dir);
    let keyring = dir.join("alice.asc");
    std::fs::write(&keyring, ALICE).expect("keyring");

    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .args(["-c", config.to_str().expect("path"), "import"])
        .arg(&keyring)
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"imported\":1"));

    // Dry run stores nothing new (still exactly one certificate).
    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .args(["-c", config.to_str().expect("path"), "import", "--dry-run"])
        .arg(&keyring)
        .output()
        .expect("run");
    assert!(output.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .args(["-c", config.to_str().expect("path"), "stats"])
        .output()
        .expect("run");
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"certificates\":1"));

    let output = Command::new(env!("CARGO_BIN_EXE_volta-delete"))
        .arg(dir.to_str().expect("path"))
        .arg(ALICE_FPR)
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .args(["-c", config.to_str().expect("path"), "stats"])
        .output()
        .expect("run");
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"certificates\":0"));
}

#[test]
fn mcp_stdio_lists_thirteen_tools() {
    let dir = tempdir("mcp");
    let config = write_config(&dir);
    let mut child = Command::new(env!("CARGO_BIN_EXE_voltactl"))
        .args(["-c", config.to_str().expect("path"), "mcp", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            "{{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{{}}}}"
        )
        .expect("write");
        writeln!(
            stdin,
            "{{\"id\":2,\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"params\":{{}}}}"
        )
        .expect("write");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(stdout.contains("\"name\":\"volta\""), "{stdout}");
    assert!(stdout.contains("volta_wkd_lookup"), "{stdout}");
    assert_eq!(stdout.matches("volta_").count(), 13, "{stdout}");
}
