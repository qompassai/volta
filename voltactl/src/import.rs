// #################################################################
// /qompassai/volta/voltactl/src/import.rs
// Qompass AI Import
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Qompass AI
//
// Volta is derived from Hagrid, the software behind
// keys.openpgp.org, and this material is licensed under the
// GNU Affero General Public License, version 3 only (see
// LICENSE-AGPL). Contributions authored by Qompass AI are
// dual-licensed under AGPL-3.0 or Apache-2.0 at the
// recipient's choice (see NOTICE); that choice does not
// extend to upstream-derived material, which remains
// AGPL-3.0 only.

use std::cmp::min;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::Result;

extern crate tempfile;

extern crate sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::armor::ReaderMode;
use openpgp::parse::{Dearmor, PacketParserBuilder, PacketParserResult, Parse};

extern crate volta_database as database;
use database::{Database, ImportResult, KeyDatabase};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::VoltaConfig;

// parsing TPKs takes time, so we benefit from some parallelism. however, the
// database is locked during the entire merge operation, so we get diminishing
// returns after the first few threads.
const NUM_THREADS_MAX: usize = 3;

#[allow(clippy::needless_collect)]
pub fn do_import(config: &VoltaConfig, dry_run: bool, input_files: Vec<PathBuf>) -> Result<()> {
    let num_threads = min(NUM_THREADS_MAX, input_files.len());
    let input_file_chunks = setup_chunks(input_files, num_threads);

    let multi_progress = Arc::new(MultiProgress::new());
    let progress_bar = multi_progress.add(ProgressBar::new(0));

    let threads: Vec<_> = input_file_chunks
        .into_iter()
        .map(|input_file_chunk| {
            let config = config.clone();
            let multi_progress = multi_progress.clone();
            thread::spawn(move || {
                import_from_files(&config, dry_run, input_file_chunk, multi_progress).unwrap();
            })
        })
        .collect();

    eprintln!("Importing in {} threads", num_threads);

    thread::spawn(move || multi_progress.join().unwrap());
    threads.into_iter().for_each(|t| t.join().unwrap());
    progress_bar.finish();

    Ok(())
}

fn setup_chunks(mut input_files: Vec<PathBuf>, num_threads: usize) -> Vec<Vec<PathBuf>> {
    let chunk_size = input_files.len().div_ceil(num_threads);
    (0..num_threads)
        .map(|_| {
            let len = input_files.len();
            input_files.drain(0..min(chunk_size, len)).collect()
        })
        .collect()
}

struct ImportStats<'a> {
    progress: &'a ProgressBar,
    filename: String,
    count_total: u64,
    count_err: u64,
    count_new: u64,
    count_updated: u64,
    count_unchanged: u64,
}

impl<'a> ImportStats<'a> {
    fn new(progress: &'a ProgressBar, filename: String) -> Self {
        ImportStats {
            progress,
            filename,
            count_total: 0,
            count_err: 0,
            count_new: 0,
            count_updated: 0,
            count_unchanged: 0,
        }
    }

    fn update(&mut self, result: Result<ImportResult>) {
        // If a new TPK starts, parse and import.
        self.count_total += 1;
        match result {
            Err(_) => self.count_err += 1,
            Ok(ImportResult::New(_)) => self.count_new += 1,
            Ok(ImportResult::Updated(_)) => self.count_updated += 1,
            Ok(ImportResult::Unchanged(_)) => self.count_unchanged += 1,
        }
        self.progress_update();
    }

    fn progress_update(&self) {
        if !self.count_total.is_multiple_of(10) {
            return;
        }
        self.progress.set_message(&format!(
            "{}, imported {:5} keys, {:5} New {:5} Updated {:5} Unchanged {:5} Errors",
            self.filename,
            self.count_total,
            self.count_new,
            self.count_updated,
            self.count_unchanged,
            self.count_err
        ));
    }
}

fn import_from_files(
    config: &VoltaConfig,
    dry_run: bool,
    input_files: Vec<PathBuf>,
    multi_progress: Arc<MultiProgress>,
) -> Result<()> {
    let db = KeyDatabase::new_internal(
        config.keys_internal_dir.as_ref().unwrap(),
        config.keys_external_dir.as_ref().unwrap(),
        config.tmp_dir.as_ref().unwrap(),
        dry_run,
    )?;

    for input_file in input_files {
        import_from_file(&db, &input_file, &multi_progress)?;
    }

    Ok(())
}

fn import_from_file(db: &KeyDatabase, input: &Path, multi_progress: &MultiProgress) -> Result<()> {
    let input_file = File::open(input)?;

    let bytes_total = input_file.metadata()?.len();
    let progress_bar = multi_progress.add(ProgressBar::new(bytes_total));
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {msg}")
            .progress_chars("##-"),
    );
    progress_bar.set_message("Starting…");

    let input_reader = &mut progress_bar.wrap_read(input_file);
    let filename = input.file_name().unwrap().to_string_lossy().to_string();
    let mut stats = ImportStats::new(&progress_bar, filename.clone());

    read_file_to_tpks(input_reader, &mut |acc| {
        let primary_key = acc[0].clone();
        let result = import_key(db, acc);
        if let Err(ref e) = result {
            let key_fpr = match primary_key {
                Packet::PublicKey(key) => key.fingerprint().to_hex(),
                Packet::SecretKey(key) => key.fingerprint().to_hex(),
                _ => "Unknown".to_owned(),
            };
            let error = format!("{}:{:05}:{}: {}", filename, stats.count_total, key_fpr, e);
            progress_bar.println(error);
        }
        stats.update(result);
    })?;

    progress_bar.finish_and_clear();
    Ok(())
}

fn read_file_to_tpks(
    reader: impl Read + Send + Sync,
    callback: &mut impl FnMut(Vec<Packet>),
) -> Result<()> {
    // Accept armored input as well as binary: operators feed import
    // from `gpg --export` in either form, and the rest of the product
    // (VKS upload) dearmors with these same settings. Dearmor::Auto
    // passes binary data through unchanged. Feeding armor straight to
    // the packet parser used to yield zero keys, silently.
    let mut ppr = PacketParserBuilder::from_reader(reader)
        .and_then(|ppb| ppb.dearmor(Dearmor::Auto(ReaderMode::VeryTolerant)).build())?;
    let mut acc = Vec::new();

    // Iterate over all packets.
    while let PacketParserResult::Some(pp) = ppr {
        // Get the packet and advance the parser.
        let (packet, tmp) = pp.next()?;
        ppr = tmp;

        if !acc.is_empty()
            && let Packet::PublicKey(_) | Packet::SecretKey(_) = packet
        {
            callback(acc);
            acc = vec![];
        }

        acc.push(packet);
    }

    // Flush the final key: the callback above only fires when a new
    // primary key begins, so the last key of the file is still pending
    // here. Dropping it used to lose one key per file, silently.
    if !acc.is_empty() {
        callback(acc);
    }

    Ok(())
}

fn import_key(db: &KeyDatabase, packets: Vec<Packet>) -> Result<ImportResult> {
    openpgp::Cert::from_packets(packets.into_iter()).and_then(|tpk| db.merge(tpk))
}

#[cfg(test)]
mod import_tests {
    use std::io::Cursor;

    use openpgp::cert::CertBuilder;
    use openpgp::serialize::{Serialize, SerializeInto};
    use tempfile::tempdir;

    use super::*;

    fn make_cert(email: &str) -> openpgp::Cert {
        CertBuilder::new()
            .add_userid(format!("Test <{email}>"))
            .generate()
            .unwrap()
            .0
    }

    fn binary(cert: &openpgp::Cert) -> Vec<u8> {
        let mut buf = Vec::new();
        cert.export(&mut buf).unwrap();
        buf
    }

    fn armored(cert: &openpgp::Cert) -> Vec<u8> {
        cert.armored().export_to_vec().unwrap()
    }

    fn collect(input: &[u8]) -> Result<Vec<Vec<Packet>>> {
        let mut keys = Vec::new();
        read_file_to_tpks(Cursor::new(input.to_vec()), &mut |packets| {
            keys.push(packets);
        })?;
        Ok(keys)
    }

    fn primary_fpr(packets: &[Packet]) -> String {
        match &packets[0] {
            Packet::PublicKey(key) => key.fingerprint().to_hex(),
            Packet::SecretKey(key) => key.fingerprint().to_hex(),
            other => panic!("first packet is not a primary key: {other:?}"),
        }
    }

    // Regression: the parser must flush the pending key at EOF. It used
    // to only fire the callback when a *new* primary key began, silently
    // dropping the last key of every file (a one-key file imported zero
    // keys, rc=0).
    #[test]
    fn single_binary_key_yields_one_key() {
        let cert = make_cert("one@invalid.example.com");
        let keys = collect(&binary(&cert)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(primary_fpr(&keys[0]), cert.fingerprint().to_hex());
    }

    #[test]
    fn two_binary_keys_yield_two_keys() {
        let a = make_cert("a@invalid.example.com");
        let b = make_cert("b@invalid.example.com");
        let mut input = binary(&a);
        input.extend_from_slice(&binary(&b));
        let keys = collect(&input).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(primary_fpr(&keys[0]), a.fingerprint().to_hex());
        assert_eq!(primary_fpr(&keys[1]), b.fingerprint().to_hex());
    }

    // The rest of the product (VKS upload, database lookup) accepts
    // armored key material; import must dearmor transparently too.
    // It used to parse armored input to zero keys, silently.
    #[test]
    fn single_armored_key_yields_one_key() {
        let cert = make_cert("armored@invalid.example.com");
        let keys = collect(&armored(&cert)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(primary_fpr(&keys[0]), cert.fingerprint().to_hex());
    }

    #[test]
    fn empty_input_yields_no_keys() {
        let keys = collect(&[]).unwrap();
        assert_eq!(keys.len(), 0);
    }

    // Adversarial: a truncated import must fail loudly, never import a
    // partial key in silence.
    #[test]
    fn truncated_final_key_is_an_error() {
        let a = make_cert("first@invalid.example.com");
        let b = make_cert("second@invalid.example.com");
        let b_bin = binary(&b);
        let mut input = binary(&a);
        input.extend_from_slice(&b_bin[..b_bin.len() / 2]);
        assert!(collect(&input).is_err());
    }

    #[test]
    fn truncated_single_key_is_an_error() {
        let bin = binary(&make_cert("cut@invalid.example.com"));
        assert!(collect(&bin[..bin.len() / 2]).is_err());
    }

    fn test_db(root: &Path) -> KeyDatabase {
        KeyDatabase::new_internal(
            root.join("internal"),
            root.join("external"),
            root.join("tmp"),
            false,
        )
        .unwrap()
    }

    fn check_lookup(db: &KeyDatabase, cert: &openpgp::Cert) {
        let query: database::Query = cert.fingerprint().to_hex().parse().unwrap();
        let found = db
            .lookup(&query)
            .unwrap()
            .expect("imported key must be in the database");
        assert_eq!(found.fingerprint(), cert.fingerprint());
    }

    // End to end (replaces the long-commented-out import test, whose
    // APIs no longer exist): a one-key file must actually land in the
    // database, for both the binary and the armored form.
    #[test]
    fn import_single_key_file() {
        let root = tempdir().unwrap();
        let db = test_db(root.path());
        let cert = make_cert("foo@invalid.example.com");
        let file = root.path().join("import-me.gpg");
        std::fs::write(&file, binary(&cert)).unwrap();

        let multi_progress = MultiProgress::new();
        import_from_file(&db, &file, &multi_progress).unwrap();

        check_lookup(&db, &cert);
    }

    #[test]
    fn import_single_armored_key_file() {
        let root = tempdir().unwrap();
        let db = test_db(root.path());
        let cert = make_cert("armored-file@invalid.example.com");
        let file = root.path().join("import-me.asc");
        std::fs::write(&file, armored(&cert)).unwrap();

        let multi_progress = MultiProgress::new();
        import_from_file(&db, &file, &multi_progress).unwrap();

        check_lookup(&db, &cert);
    }
}
