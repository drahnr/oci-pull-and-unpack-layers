mod util;
use fs::os::unix::fs::FileExt;
mod errors;
use errors::*;
use fs_err as fs;
use libcontainer::{
    container::{builder::ContainerBuilder, ContainerStatus},
    rootfs::Device,
    syscall::syscall::SyscallType,
};
use oci_distribution::manifest::OciManifest;
use oci_distribution::manifest::{
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
};
use oci_spec::{
    image::{Arch, ImageConfigurationBuilder},
    runtime::{LinuxNamespace, Spec},
};
use std::{os::unix::fs::chroot, path::PathBuf};

const LOG_TARGET: &str = "foo";
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

    async fn run(&self, image_uri: &'static str) -> color_eyre::eyre::Result<()> {
        gum::info!(target: LOG_TARGET, "Setting up dirs");

        let layer_blob_dir = self.blob_store_dir();
        let manifest_dir = self.manifest_store_dir();

        fs::create_dir_all(&layer_blob_dir)?;
        let manifest_dir = manifest_dir.join("fedora-shuold-be-image-id"); // bonkers
        fs::create_dir_all(&manifest_dir)?;
        let manifest_path = manifest_dir.join("manifest.json");

        let cfg = oci_distribution::client::ClientConfig {
            protocol: oci_distribution::client::ClientProtocol::Https,
            ..Default::default()
        };

        let mut registry_client = oci_distribution::Client::new(cfg);
        let auth = oci_distribution::secrets::RegistryAuth::Anonymous;

        let reference: oci_distribution::Reference = image_uri.parse()?;

        let (manifest, _) = registry_client
            .pull_image_manifest(&reference, &auth)
            .await?;

        gum::debug!(target: LOG_TARGET, "manifest for {image_uri}: {manifest:?}");

        let dest = std::path::PathBuf::from(dirs::home_dir().unwrap()).join("unpack");
        let _ = fs_err::remove_dir_all(&dest);
        fs_err::create_dir_all(&dest)?;

        for (idx, layer) in manifest.layers.iter().enumerate() {
            gum::info!(
                "Working on layer#{idx}: {digest}",
                idx = idx,
                digest = &layer.digest
            );
            let layer_blob_path =
                layer_blob_dir.join(&layer.digest.split(":").skip(1).next().unwrap());
            // fs_err::create_dir_all(&layer_blob_path)?;
            // TODO use filelock here, to avoid accidental concurrency fuckups

            if let Ok(true) = tokio::fs::metadata(&layer_blob_path).await.map(|x| {
                x.is_file() && !x.is_symlink() && {
                    {
                        let mut digest = <sha2::Sha256 as sha2::digest::Digest>::new();
                        let Ok(mut data) = fs_err::File::open(&layer_blob_path) else {
                            return false;
                        };
                        use sha2::Digest;
                        let mut buf = [0; 1 << 16];
                        let mut acc = 0;
                        while let Ok(n) = data.read(&mut buf[..]) {
                            if n == 0 {
                                break;
                            }
                            acc += n;
                            gum::info!("Read total of {acc} byte");
                            digest.input(&buf[..n]);
                        }
                        dbg!(digest.result()).to_vec()
                    }
                } == dbg!(const_hex::decode(
                    &layer.digest.split(":").skip(1).next().unwrap()
                ))
                .unwrap()
            }) {
                // TODO check matching sha256
                gum::debug!(target: LOG_TARGET, "Layer blob already exists on disk, skipping download");
            } else {
                let mut blob_file = fs_err::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&layer_blob_path)?;
                let mut blob_file = tokio::fs::File::from_std(blob_file.into());
                registry_client
                    .pull_blob(&reference, &layer.digest, &mut blob_file)
                    .await?;
                gum::debug!(target: LOG_TARGET, "Downloaded layer blob for {image_uri}");
            }

            gum::info!(target: LOG_TARGET, "Loading blob for {} from {}", &image_uri, layer_blob_path.display());

            let blob = fs_err::read(&layer_blob_path)?; // bonkers
            let mut blob = &blob[..];

            fn unpack<T: std::io::Read>(
                arch: &mut tar::Archive<T>,
                dest: &std::path::Path,
            ) -> std::io::Result<()> {
                arch.set_unpack_xattrs(false);
                arch.set_overwrite(true);
                arch.set_preserve_mtime(false);
                arch.set_preserve_permissions(false);
                arch.set_preserve_ownerships(false);
                arch.unpack(&dest)?;
                Ok(())
            }
            // unpacking to target dir
            match dbg!(layer.media_type.as_str()) {
                // FIXME verify these are identicaly for sure
                IMAGE_LAYER_MEDIA_TYPE | IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => {
                    let mut arch = tar::Archive::new(&mut blob);
                    unpack(&mut arch, &dest)?;
                }
                IMAGE_LAYER_GZIP_MEDIA_TYPE | IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => {
                    let mut buf = flate2::read::GzDecoder::new(&mut blob);
                    let mut arch = tar::Archive::new(&mut buf);
                    unpack(&mut arch, &dest)?;
                }
                _ => {
                    todo!()
                }
            }
        }

        gum::error!(target: LOG_TARGET, "Now what!?");

        Ok(())
    }
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    pretty_env_logger::formatted_timed_builder()
        .filter_level(gum::LevelFilter::Trace)
        .init();
    let houdini = Houdini {
        extract_base: PathBuf::from("/tmp/oci/extract_base"),
        image_dir: PathBuf::from("/tmp/oci/tar_folder"),
    };
    houdini
        .run("registry.fedoraproject.org/fedora:latest")
        .await?;
    Ok(())
}
