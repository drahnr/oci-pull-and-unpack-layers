// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2023 Gensyn Ltd. <admin@gensyn.ai>. All rights reserved.

//! This crate exposes shared functionality across the codebase.

use super::*;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::{
    io::{Read, Seek},
    path::Path,
    sync::Arc,
};
use tar::Archive;

/// Does `tar -czvf [temporary file] <dir>` then reads temporary file and returns it as `Vec<u8>`.
pub fn tar_gz_dir(dir: &Path) -> std::io::Result<Arc<Vec<u8>>> {
    let mut tmp_file = tempfile::tempfile()?;

    {
        let enc = GzEncoder::new(&tmp_file, Compression::default());
        let mut tar_builder = tar::Builder::new(enc);
        // we only care about the contents + makes testing possible
        tar_builder.mode(tar::HeaderMode::Deterministic);
        tar_builder.append_dir_all("", dir)?;
        tar_builder.finish()?;
    }

    tmp_file.rewind()?;

    let mut data = Vec::new();
    tmp_file.read_to_end(&mut data)?;

    Ok(Arc::new(data))
}

/// Unpacks the `*.tar.gz` file contents to directory: `tar -xvf <data> -C <dir>`
pub fn untar_gz_file<R: std::io::Read>(data: R, dir: &Path) -> std::io::Result<()> {
    let tar = GzDecoder::new(data);
    let mut archive = Archive::new(tar);
    archive.unpack(dir)?;

    Ok(())
}
