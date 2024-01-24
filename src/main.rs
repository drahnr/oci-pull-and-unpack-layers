mod util;
use fs::os::unix::fs::FileExt;
mod errors;
use errors::*;
use fs_err as fs;
use libcontainer::{
    container::{builder::ContainerBuilder, ContainerStatus},
    rootfs::Device,
    syscall::syscall::SyscallType,
    workload::default::DefaultExecutor,
};
use oci_distribution::manifest::OciManifest;
use oci_distribution::manifest::{
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
};
use oci_spec::{
    image::{Arch, ImageConfigurationBuilder},
    runtime::{Capability, Linux, LinuxNamespace, Mount, ProcessBuilder, Root, RootBuilder, Spec},
};
use std::{
    os::unix::fs::{chown, chroot, PermissionsExt},
    path::PathBuf,
};

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
        let mut manifest_f = fs_err::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&manifest_path)?;
        manifest_f.write_all(serde_json::to_string(&manifest)?.as_bytes())?;
        gum::info!(target: LOG_TARGET, "Wrote manifest content to {}", manifest_path.display());

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
                            gum::trace!("Read total of {acc} byte");
                            digest.input(&buf[..n]);
                        }
                        digest.result().to_vec()
                    }
                } == const_hex::decode(
                    &layer.digest.split(":").skip(1).next().unwrap(),
                )
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

            let mut blob = fs_err::OpenOptions::new()
                .read(true)
                .open(&layer_blob_path)?; // bonkers

            fn unpack<T: std::io::Read + std::io::Seek>(
                arch: &mut tar::Archive<T>,
                dest: &std::path::Path,
            ) -> std::io::Result<()> {
                let mut metadata = dest.metadata()?;
                metadata.permissions().set_mode(0o777);

                arch.set_unpack_xattrs(true);
                arch.set_overwrite(true);
                arch.set_mask(0o022);
                arch.set_preserve_mtime(false);
                arch.set_preserve_permissions(true);
                arch.set_preserve_ownerships(false);
                arch.unpack(&dest)?;
                Ok(())
            }
            fn unpack_akv(
                arch: &mut akv::reader::ArchiveReader<'_>,
                dest: &std::path::Path,
            ) -> std::io::Result<()> {
                while let Some(entry) = arch.next_entry()? {
                    let in_tar_relative_path = entry.pathname_utf8()?;
                    let unpack_file_dest = dest.join(in_tar_relative_path);
                    gum::debug!(target: LOG_TARGET, "Unpacking {} to {}", in_tar_relative_path, unpack_file_dest.display());
                    let mut entry_reader = entry.into_reader();
                    let mut dest_f = fs_err::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(unpack_file_dest)?;
                    std::io::copy(&mut entry_reader, &mut dest_f)?;
                }
                Ok(())
            }
            // unpacking to target dir
            match dbg!(layer.media_type.as_str()) {
                // FIXME verify these are identicaly for sure
                IMAGE_LAYER_MEDIA_TYPE | IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => {
                    let mut arch = akv::reader::ArchiveReader::open_io(&mut blob)?;
                    // let mut arch = tar::Archive::new(&mut blob);
                    // unpack(&mut arch, &dest)?;
                    unpack_akv(&mut arch, &dest)?;
                }
                IMAGE_LAYER_GZIP_MEDIA_TYPE | IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => {
                    // `tar-rs` fails with hardlinks and some permissions, `libarchive` works just fine.
                    // let mut blob = flate2::read::GzDecoder::new(&mut blob);
                    // let mut arch = tar::Archive::new(&mut blob);
                    // unpack(&mut arch, &dest)?;
                    let mut gzblob = flate2::read::GzDecoder::new(&mut blob);
                    let mut decompressed =
                        tempfile::tempfile_in(layer_blob_path.parent().unwrap())?;
                    std::io::copy(&mut gzblob, &mut decompressed)?;
                    let mut arch = akv::reader::ArchiveReader::open_io(&mut decompressed)?;
                    unpack_akv(&mut arch, &dest)?;
                }
                _ => {
                    todo!()
                }
            }
        }

        self.execution(dest.as_path())?;
        gum::error!(target: LOG_TARGET, "Now what!?");

        Ok(())
    }

    fn execution(
        &self,
        unpacked_container_contents: &std::path::Path,
    ) -> color_eyre::eyre::Result<()> {
        let root_dir = unpacked_container_contents;
        assert!(fs_err::metadata(&root_dir)?.is_dir());

        if false {
            let mut rootfs = libcontainer::rootfs::RootFS::new();

            let mut spec = Spec::default(); // load(self.manifest_store_dir().join("manifest.json"))?;
            let mut linux = Linux::default();
            linux.set_rootfs_propagation(Some("shared".to_owned()));
            let mut root = RootBuilder::default()
                .readonly(true)
                .path(&root_dir)
                .build()?;
            spec.set_linux(Some(linux))
                .set_mounts(None)
                .set_hostname("trapped".to_owned().into())
                .set_root(Some(root))
                .set_hooks(None)
                .set_annotations(None)
                .set_domainname(Some("gensyn.ai".to_owned()));
            gum::info!(target: LOG_TARGET, "Spec {spec:?}");
            rootfs.prepare_rootfs(&spec, &root_dir, true, false)?;

            // let mut process = ProcessBuilder::default();
            // process.capabilities(Capability::SysAdmin).no_new_privileges(true).cwd(&root_dir).env(None).command_line(value)

            let uuid = uuid::Uuid::new_v4();
            let mut container =
                ContainerBuilder::new(uuid.as_hyphenated().to_string(), SyscallType::default());
            let container = container
                .with_executor(DefaultExecutor {})
                .with_root_path(&root_dir)?
                .as_init("/tmp/oci/exec")
                .with_detach(false)
                .with_systemd(false)
                .build()?;
        } else {
            let command_as_string = "cat /etc/os-release";
            gum::info!(target: LOG_TARGET, "Attempting to run `sh -c {}` in {}", command_as_string, root_dir.display());
            let mut command = std::process::Command::new("sh");
            command.arg("-c");
            command.args(command_as_string.split(" "));
            command.current_dir(&root_dir);
            command.env_clear().env(
                "PATH",
                &format!(
                    "{root_dir}/bin:{root_dir}/usr/bin/:{root_dir}/usr/local/bin:{root_dir}/sbin",
                    root_dir = root_dir.display()
                ),
            );
            dbg!(&command);

            let output = command.output()?;
            log_command_output(&output)?;

            if !output.status.success() {
                Err(Error::NoContainerCommandExecutionFailed)?
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    pretty_env_logger::formatted_timed_builder()
        .filter_level(gum::LevelFilter::Debug)
        .init();
    let houdini = Houdini {
        extract_base: PathBuf::from("/tmp/oci/extract_base"),
        image_dir: PathBuf::from("/tmp/oci/tar_folder"),
    };
    let ubuntu = "docker.io/library/ubuntu:latest";
    let fedora = "registry.fedoraproject.org/fedora:latest";
    let quay = "quay.io/drahnr/rust-glibc-builder";
    let busybox = "docker.io/library/busybox:latest";
    houdini.run(quay).await?;
    Ok(())
}

/// Unified parsing of the process output streams.
///
/// Log both `stdout` and `stderr` while adding line numbers to each.
fn log_command_output(
    output: &std::process::Output,
) -> std::result::Result<(), std::str::Utf8Error> {
    gum::info!(target: LOG_TARGET, "Output status = {:?}", output.status);
    std::str::from_utf8(&output.stdout)?
        .split('\n')
        .enumerate()
        .for_each(|(_, line)| gum::info!(target: LOG_TARGET, "stdout: {}", line));
    std::str::from_utf8(&output.stderr)?
        .split('\n')
        .enumerate()
        .for_each(|(_, line)| gum::info!(target: LOG_TARGET, "stderr: {}", line));
    Ok(())
}
