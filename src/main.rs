mod util;
use color_eyre::eyre::Context;
use util::*;
mod errors;
use errors::*;
use oci_registry_client::manifest::Digest;

use fs_err as fs;

const LOG_TARGET: &str = "foo";
use std::path::PathBuf;
use std::str::FromStr;

use std::io::{Read, Write};

/// Representation of an image reference
///
/// Can either be the registry uri `$registryurl/$user/$container`
/// or a sha (all lowercase) with 64 characters `a989a...df93e` (no ellipsis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageId {
    /// A SHA256 identifier for an image.
    Sha256(String),
    /// A URI identifier for an image.
    Uri(String),
}

impl ImageId {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Sha256(s) => s.as_str(),
            Self::Uri(s) => s.as_str(),
        }
    }
}

impl FromStr for ImageId {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use once_cell::sync::Lazy;
        use regex::Regex;

        static RE_SHA256: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^\s*([a-z0-9]{64})\s*$").unwrap());
        static RE_URI: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^\s*(?P<all>(?P<registry>[A-Za-z0-9_-]+\..{1,12})/(?P<user>[A-Za-z0-9_-]+)/(?P<image>[A-Za-z0-9_-]+)(?P<tag>:[A-Za-z0-9_-]+))\s*$").unwrap()
        });

        let s: &str = s.trim();
        let ec = || Error::IncompleteImageId {
            wannabe_id: s.to_owned(),
        };
        if let Some(captures) = RE_SHA256.captures(s) {
            Ok(Self::Sha256(
                captures.get(1).ok_or_else(ec)?.as_str().to_string(),
            ))
        } else if let Some(captures) = RE_URI.captures(s) {
            let _registry = captures.name("registry").ok_or_else(ec)?;
            let _name = captures.name("user").ok_or_else(ec)?;
            let _image = captures.name("image").ok_or_else(ec)?;
            let _tag = captures.name("tag").ok_or_else(ec)?;
            let all = captures.name("all").ok_or_else(ec)?;
            Ok(Self::Uri(all.as_str().to_string()))
        } else {
            Err(Error::IncompleteImageId {
                wannabe_id: s.to_owned(),
            })
        }
    }
}

#[derive(Debug, Default)]
pub struct Houdini {
    /// The folder where to place the downloaded `tar.gz`.
    image_dir: PathBuf,
    /// The temporary folder, in which to extract the `tar.gz` image to.
    extract_base: PathBuf,
}

impl Houdini {
    fn rootfs_dir(&self, image_id: &ImageId) -> PathBuf {
        self.extract_base.join(image_id.as_str()).join("rootfs")
    }

    fn blob_store_dir(&self) -> PathBuf {
        self.image_dir.join("layers")
    }

    fn manifest_store_dir(&self) -> PathBuf {
        self.image_dir.join("manifests")
    }

    fn run(&self) -> color_eyre::eyre::Result<()> {
        let image_uri = "fedora:latest";
        // let image_id = ImageId::from_str(image_uri)?;

        gum::info!(target: LOG_TARGET, "Requesting from registry");
        let registry = oci_registry_client::DockerRegistryClientV2::new(
            "registry.fedoraproject.org",
            "https://registry.fedoraproject.org",
            "https://registry.fedoraproject.org",
        );
        let rt = tokio::runtime::Runtime::new()?;

        gum::info!(target: LOG_TARGET, "Setting up dirs");

        let layer_blob_dir = self.blob_store_dir();
        let manifest_dir = self.manifest_store_dir();

        let layer_digests = rt.block_on(async move {

            gum::info!(target: LOG_TARGET, "Fetch fedora latest");
            let manifest = registry.manifest("fedora", "latest").await?;
            gum::debug!(target: LOG_TARGET, "manifest for {image_uri}: {manifest:?}");

            fs::create_dir_all(&layer_blob_dir)?;
            let manifest_dir = manifest_dir.join("fedora-shuold-be-image-id"); // bonkers
            fs::create_dir_all(&manifest_dir)?;
            let manifest_path = manifest_dir.join("manifest.json");

            for (i, layer) in manifest.layers.iter().enumerate() {
                gum::trace!(target: LOG_TARGET, "Layer: {idx}, {layer}", idx=i, layer=&layer.digest.hash);
                let layer_blob_path = layer_blob_dir.join(&layer.digest.hash);
                // TODO use filelock here, to avoid accidental concurrency fuckups

                if let Ok(true) = fs_err::metadata(&layer_blob_path)
                .map(|metadata| { dbg!(metadata.is_file()) && dbg!(!metadata.is_symlink()) && {
                    let mut digest = <sha2::Sha256 as sha2::digest::Digest>::new();
                    if let Ok(mut data) = fs_err::File::open(&layer_blob_path) {
                        use sha2::Digest;
                        let mut buf = [0u8; 8192];
                        gum::warn!(target: LOG_TARGET, "Hashing...");
                        while let Ok(n) = data.read(&mut buf[..]) {
                            digest.input(&buf[..n]);
                        }
                        gum::warn!(target: LOG_TARGET, "Hash calc complete");

                        let eval = layer.digest == oci_registry_client::manifest::Digest::from_sha256(digest.result());
                        gum::warn!(target: LOG_TARGET, "Hashes matchin? {eval}");
                        return dbg!(eval)
                        } else {
                            gum::warn!(target: LOG_TARGET, "File exists, but couldn't read it {layer_blob_path:?}");
                        return dbg!(false)
                    }
                } })
                {
                    // TODO check matching sha256
                    gum::debug!(target: LOG_TARGET, "Layer blob already exists on disk, skipping download");
                } else {
                    gum::warn!(target: LOG_TARGET, "Downloading layer blob...");

                    fs::create_dir_all(layer_blob_path.parent().expect("Must have a parent. qed"))?;
                    let mut out_file = fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(layer_blob_path)?;
                    gum::debug!(target: LOG_TARGET, "Sending req to registry, out file ready for input");
                    let mut blob = registry.blob(image_uri, &layer.digest).await.wrap_err("Blob retrieve")?;
                    gum::debug!(target: LOG_TARGET, "Got response for blob");

                    let mut acc = 0;
                    while let Some(chunk) = blob.chunk().await.wrap_err("Chunk retrieve failed")? {
                        acc += chunk.len();
                        gum::debug!(target: LOG_TARGET, "Received bytes (total: {acc})");
                        out_file.write_all(&chunk)?;
                    }
                    gum::debug!(target: LOG_TARGET, "Downloaded layer {i} blob for {image_uri}");
                }
            }
            gum::trace!(target: LOG_TARGET, "Downloaded all layers");
            Ok::<_, color_eyre::eyre::ErrReport>(Vec::from_iter(manifest.layers.iter().map(|x| x.digest.hash.clone())))
        })?;

        gum::error!(target: LOG_TARGET, "Now what?");

        let _rootfs_desc = oci_spec::image::RootFsBuilder::default()
            .diff_ids(layer_digests)
            .build()?;

        gum::error!(target: LOG_TARGET, "Now what!?");

        Ok(())
    }
}

fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    pretty_env_logger::formatted_timed_builder()
        .filter_level(gum::LevelFilter::Trace)
        .init();
    let houdini = Houdini {
        extract_base: PathBuf::from("/tmp/oci/extract_base"),
        image_dir: PathBuf::from("/tmp/oci/tar_folder"),
    };
    houdini.run()?;
    Ok(())
}
