use std::{
    ffi::OsString,
    fs::{File},
    io::{BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{anyhow, Context, Result};
use avbroot::{
    crypto::{self, PassphraseSource},
    format::{
        payload::{PayloadHeader, PayloadWriter},
    },
    stream::{self, FromReader},
};
use clap::Parser;
use rsa::RsaPrivateKey;

#[derive(Debug, Parser)]
struct Cli {
    /// Path to old unsigned payload.bin
    #[arg(long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output signed payload.bin
    #[arg(long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Private key for signing the payload.bin.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_name = "ENV_VAR", value_parser, group = "pass")]
    pass_env_var: Option<OsString>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_name = "FILE", value_parser, group = "passphrase")]
    pass_file: Option<PathBuf>,
}

/// Sign a (potentially unsigned) payload without making any other
/// modifications to it.
fn sign_payload(
    unsigned_payload: &Path,
    writer: impl Write,
    key: &RsaPrivateKey,
) -> Result<(String, u64)> {
    let inc_raw_reader = File::open(unsigned_payload)
        .with_context(|| format!("Failed to open for reading: {unsigned_payload:?}"))?;
    let mut inc_reader = BufReader::new(inc_raw_reader);
    let inc_header = PayloadHeader::from_reader(&mut inc_reader)
        .with_context(|| format!("Failed to parse payload header: {unsigned_payload:?}"))?;

    let mut payload_writer = PayloadWriter::new(writer, inc_header.clone(), key.clone())
        .context("Failed to write payload header")?;

    while payload_writer
        .begin_next_operation()
        .context("Failed to begin next payload blob entry")?
    {
        let name = payload_writer.partition().unwrap().partition_name.clone();
        let operation = payload_writer.operation().unwrap();

        let Some(data_length) = operation.data_length else {
            // Otherwise, this is a ZERO/DISCARD operation.
            continue;
        };

        // Copy from the original payload.
        let pi = payload_writer.partition_index().unwrap();
        let oi = payload_writer.operation_index().unwrap();
        let orig_partition = &inc_header.manifest.partitions[pi];
        let orig_operation = &orig_partition.operations[oi];

        let data_offset = orig_operation
            .data_offset
            .and_then(|o| o.checked_add(inc_header.blob_offset))
            .ok_or_else(|| anyhow!("Missing data_offset in partition #{pi} operation #{oi}"))?;

        inc_reader
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek original payload to {data_offset}"))?;

        stream::copy_n(
            &mut inc_reader,
            &mut payload_writer,
            data_length,
            &Arc::new(AtomicBool::new(false)),
        )
        .with_context(|| format!("Failed to copy from original payload: {name}"))?;
    }

    let (_, p, m) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok((p, m))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut properties = None;
    let mut payload_metadata_size = None;

    let passphrase_source = if let Some(v) = &cli.pass_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &cli.pass_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", cli.key))
    };

    let key = crypto::read_pem_key_file(&cli.key, &passphrase_source)
        .with_context(|| format!("Failed to load key: {:?}", cli.key))?;

    println!("Signing the OTA payload, please wait...");

    let unsigned_payload = Path::new(&cli.input);
    let mut writer = File::create(&cli.output)?;

    let (p, m) = sign_payload(&unsigned_payload, &mut writer, &key)?;

    properties = Some(p);
    payload_metadata_size = Some(m);

    if let Some(props) = properties {
        println!("Properties: {:?}", props);
    }

    if let Some(size) = payload_metadata_size {
        println!("Payload_metadata_size: {:?}", size);
    }

    Ok(())
}
