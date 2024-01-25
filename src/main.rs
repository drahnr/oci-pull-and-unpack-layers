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
    runtime::{
        Capability, Linux, LinuxCapabilities, LinuxCapabilitiesBuilder, LinuxNamespace, Mount,
        ProcessBuilder, Root, RootBuilder, Spec,
    },
};
use std::{
    fs::Permissions,
    io::{Cursor, Seek, SeekFrom},
    os::unix::fs::{chown, chroot, MetadataExt, PermissionsExt},
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

fn unpack<T: std::io::Read + std::io::Seek>(
    mut arch: tar::Archive<T>,
    blob_src: &std::path::Path,
    unpack_dest: &std::path::Path,
) -> std::io::Result<()> {
    // without it, `motd.d` won't unpack successfully
    let mut metadata = unpack_dest.metadata()?;
    metadata.permissions().set_mode(0o777);

    let mask = 0o022;
    gum::warn!(target: LOG_TARGET, "Unpacking (tar-rs) layer {} to: {}", blob_src.display(), unpack_dest.display());
    arch.set_unpack_xattrs(true);
    arch.set_overwrite(true);
    arch.set_mask(mask);
    arch.set_preserve_mtime(false);
    arch.set_preserve_permissions(true);
    arch.set_preserve_ownerships(false);
    // broken, doesn't handle hardlinks properly and causes permission issues
    // arch.unpack(unpack_dest)?;
    // return Ok(());

    for entry in arch.entries()? {
        let mut entry = entry?;
        let in_tar_relative_path = entry.path()?.to_path_buf();
        let in_tar_relative_path = PathBuf::from_iter(in_tar_relative_path.components().skip(1));
        let unpack_file_dest = unpack_dest.join(&in_tar_relative_path);

        fs_err::create_dir_all(unpack_file_dest.parent().unwrap())?;
        match dbg!(entry.header().entry_type()) {
            tar::EntryType::Directory => {
                fs_err::create_dir_all(unpack_file_dest)?;
            }
            tar::EntryType::Regular => {
                let mut dest_f = fs_err::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(unpack_file_dest)?;
                std::io::copy(&mut entry, &mut dest_f)?;
            }
            _ => {}
        }
    }

    let mut inner = arch.into_inner();
    inner.seek(SeekFrom::Start(0))?;
    let mut arch = tar::Archive::new(inner);
    for entry in arch.entries()? {
        let mut entry = entry?;
        let in_tar_relative_path = entry.path()?.to_path_buf();
        let in_tar_relative_path = PathBuf::from_iter(in_tar_relative_path.components().skip(1));
        let unpack_file_dest = unpack_dest.join(&in_tar_relative_path);
        gum::info!(target: LOG_TARGET, "Unpacking {} to {}", in_tar_relative_path.display(), unpack_file_dest.display());

        fs_err::create_dir_all(unpack_file_dest.parent().unwrap())?;
        match dbg!(entry.header().entry_type()) {
            tar::EntryType::Link => {
                let link_to_create = entry.link_name()?.unwrap().to_path_buf();
                let _ = fs_err::hard_link(link_to_create, unpack_file_dest);
            }
            tar::EntryType::Symlink => {
                let link_to_create = entry.link_name()?.unwrap().to_path_buf();
                let _ = fs_err::soft_link(link_to_create, unpack_file_dest);
            }
            tar::EntryType::Directory | tar::EntryType::Regular => { /* already handled */ }
            et => {
                gum::info!(target: LOG_TARGET, "{:?}, unhandled, skipping..", et);
            }
        }
    }

    let mut inner = arch.into_inner();
    inner.seek(SeekFrom::Start(0))?;
    let mut arch = tar::Archive::new(inner);
    for entry in arch.entries()? {
        let mut entry = entry?;
        let in_tar_relative_path = entry.path()?.to_path_buf();
        let in_tar_relative_path = PathBuf::from_iter(in_tar_relative_path.components().skip(1));
        let unpack_file_dest = unpack_dest.join(&in_tar_relative_path);

        if !entry.header().entry_type().is_symlink() {
            use std::os::unix::prelude::*;
            let mode = entry.header().mode()?;
            let mode = mode & !mask;
            let perm = std::fs::Permissions::from_mode(mode as _);
            if let Err(e) = fs_err::set_permissions(&unpack_file_dest, perm) {
                gum::error!(target: LOG_TARGET, "Failed to set permissions ({:o}) for {}", mode, unpack_file_dest.display());
            }
        }
    }

    // TODO fixup permissions in a 3rd loop
    Ok(())
}
fn unpack_akv(
    arch: &mut akv::reader::ArchiveReader<'_>,
    blob_src: &std::path::Path,
    unpack_dest: &std::path::Path,
) -> std::io::Result<()> {
    gum::warn!(target: LOG_TARGET, "Unpacking (akv) layer {} to: {}", blob_src.display(), unpack_dest.display());

    while let Some(entry) = arch.next_entry()? {
        let in_tar_relative_path = entry.pathname_utf8()?;
        let unpack_file_dest = unpack_dest.join(in_tar_relative_path);
        gum::info!(target: LOG_TARGET, "Unpacking {} to {}", in_tar_relative_path, unpack_file_dest.display());
        let mut entry_reader = entry.into_reader();
        if let Ok(mut dest_f) = fs_err::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&unpack_file_dest)
        {
            std::io::copy(&mut entry_reader, &mut dest_f)?;
        } else {
            gum::warn!(target: LOG_TARGET, "Failed to write to {}", unpack_file_dest.display());
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct Houdini {
    /// The folder where to place the downloaded `tar.gz`.
    image_dir: PathBuf,
    /// The temporary folder, in which to extract the `tar.gz` image to.
    extract_base: PathBuf,
}

impl Houdini {
    fn rootfs_dir(&self, image_id: &uuid::Uuid) -> PathBuf {
        self.extract_base
            .join(image_id.as_hyphenated().to_string())
            .join("rootfs")
    }

    fn blob_store_dir(&self) -> PathBuf {
        self.image_dir.join("layers")
    }

    fn manifest_store_dir(&self) -> PathBuf {
        self.image_dir.join("manifests")
    }

    async fn run(&self, image_uri: &'static str) -> color_eyre::eyre::Result<()> {
        gum::info!(target: LOG_TARGET, "Setting up dirs");
        let uuid = uuid::Uuid::new_v4();

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
        manifest_f.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
        gum::info!(target: LOG_TARGET, "Wrote manifest content to {}", manifest_path.display());

        let unpack_dest = self.rootfs_dir(&uuid);
        let _ = fs_err::remove_dir_all(&unpack_dest);
        fs_err::create_dir_all(&unpack_dest)?;

        gum::info!(target: LOG_TARGET, "Unpacking into rootfs: {}", unpack_dest.display());

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

            if let Ok(true) = tokio::fs::metadata(&layer_blob_path).await.map(|metadata| {
                dbg!(metadata.size()) > 4096 && metadata.is_file() && !metadata.is_symlink() && {
                    {
                        let mut digest = <sha2::Sha256 as sha2::digest::Digest>::new();
                        let Ok(mut data) = fs_err::File::open(&layer_blob_path) else {
                            return false;
                        };
                        use sha2::Digest;
                        let mut buf = [0; 1 << 20];
                        let mut acc = 0;
                        while let Ok(n) = data.read(&mut buf[..]) {
                            if n == 0 {
                                break;
                            }
                            acc += n;
                            gum::trace!("Read total of {acc} byte");
                            digest.input(&buf[..n]);
                        }
                        let digest = digest.result().to_vec();
                        dbg!(const_hex::encode(&digest[..]));
                        digest
                    }
                }
                    == const_hex::decode(dbg!(&layer.digest.split(":").skip(1).next().unwrap()))
                        .unwrap()
            }) {
                gum::info!(target: LOG_TARGET, "Layer blob already exists on disk {}, skipping download", layer_blob_path.display());
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
                gum::info!(target: LOG_TARGET, "Downloaded layer blob for {image_uri}");
            }

            gum::info!(target: LOG_TARGET, "Loading blob for {} from {}", &image_uri, layer_blob_path.display());

            let mut blob = fs_err::OpenOptions::new()
                .read(true)
                .open(&layer_blob_path)?; // bonkers

            // unpacking to target dir
            match dbg!(layer.media_type.as_str()) {
                // FIXME verify these are identicaly for sure
                IMAGE_LAYER_MEDIA_TYPE | IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => {
                    let mut arch = tar::Archive::new(&mut blob);
                    unpack(arch, &layer_blob_path, &unpack_dest)?;
                    continue;
                    // let mut arch = akv::reader::ArchiveReader::open_io(&mut blob)?;
                    // unpack_akv(&mut arch, &layer_blob_path,  &unpack_dest)?;
                }
                IMAGE_LAYER_GZIP_MEDIA_TYPE | IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => {
                    let mut gzdecoder = flate2::read::GzDecoder::new(&mut blob);
                    let mut decompressed =
                        tempfile::tempfile_in(layer_blob_path.parent().unwrap())?;
                    std::io::copy(&mut gzdecoder, &mut decompressed)?;
                    decompressed.seek(std::io::SeekFrom::Start(0))?;
                    // `tar-rs` fails with hardlinks and some permissions, `libarchive` works just fine.
                    let mut arch = tar::Archive::new(decompressed);
                    unpack(arch, &layer_blob_path, &unpack_dest)?;
                    continue;
                    // let mut arch = akv::reader::ArchiveReader::open_io(&mut decompressed)?;
                    // unpack_akv(&mut arch, &layer_blob_path, &unpack_dest)?;
                }
                _ => {
                    todo!()
                }
            }
        }
        gum::info!(target: LOG_TARGET, "Starting boundaries setup");

        self.execution(uuid, unpack_dest.as_path())?;
        gum::error!(target: LOG_TARGET, "Now what!?");

        Ok(())
    }

    fn execution(
        &self,
        container_id: uuid::Uuid,
        unpacked_container_contents: &std::path::Path,
    ) -> color_eyre::eyre::Result<()> {
        let root_dir = unpacked_container_contents;
        let bundle_dir = root_dir.parent().unwrap();

        assert!(fs_err::metadata(&root_dir)?.is_dir());

        if true {
            // create /dev in case it doesn't exist yet, it likely won't
            // let _ = fs_err::create_dir(dbg!(root_dir.join("dev")));
            // fs_err::set_permissions(root_dir.join("dev"), Permissions::from_mode(0o777_u32))?; // otherwise we can't symlink /proc/kcore to /dev/kcore in the intermediate process
            // let _ = fs_err::create_dir(dbg!(root_dir.join("proc")));
            // fs_err::set_permissions(root_dir.join("proc"), Permissions::from_mode(0o777_u32))?;

            let caps = LinuxCapabilities::default();
            // .ambient(Capability::SysAdmin)
            // .inheritable(Capability::SysAdmin)
            // .effective(Capability::SysAdmin).build()?;

            let mut spec = Spec::default(); // load(self.manifest_store_dir().join("config.json"))?;
            let mut root = RootBuilder::default();
            let mut linux = Linux::rootless(1000, 1000);
            linux.set_rootfs_propagation(Some("shared".to_owned()));

            let mut process = oci_spec::runtime::Process::default();
            process
                .set_env(Some(vec![
                    "PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/bin".to_owned(),
                ]))
                .set_cwd(PathBuf::from("/"))
                .set_args(Some(Vec::from_iter(
                    ["bash", "-c", "ls", "-al"]
                        .into_iter()
                        .map(|x| x.to_owned()),
                )))
                .set_capabilities(Some(caps))
                .set_no_new_privileges(Some(true));

            let root = RootBuilder::default()
                .path(&root_dir)
                .readonly(false)
                .build()?;
            spec.set_linux(Some(linux))
                .set_mounts(Some(vec![]))
                .set_hostname("trapped".to_owned().into())
                .set_root(Some(root))
                .set_hooks(None)
                .set_annotations(None)
                .set_domainname(Some("gensyn.ai".to_owned()))
                .set_process(Some(process));
            gum::info!(target: LOG_TARGET, "Spec {spec:?}");

            // not sure this is required?
            // if it's enabled, get duplicate symlink errors
            // let mut rootfs = libcontainer::rootfs::RootFS::new();
            // rootfs.prepare_rootfs(&spec, &root_dir, true, true)?;

            let config_json = serde_json::to_string_pretty(&spec).unwrap();
            fs_err::write(bundle_dir.join("config.json"), config_json.as_bytes()).unwrap();

            let mut container = ContainerBuilder::new(
                container_id.as_hyphenated().to_string(),
                SyscallType::default(),
            );
            let container_state_dir = self.extract_base.join("container-state").join(container_id.hyphenated().to_string());
            fs_err::create_dir_all(&container_state_dir)?;
            let mut container = container
                .with_executor(DefaultExecutor {})
                .with_root_path(&container_state_dir)?
                .validate_id()?
                .as_init(&bundle_dir)
                .with_detach(false)
                .with_systemd(false)
                .build()?;
            container.start().or_else(|e| {
                let _ = dbg!(container.delete(true));
                Err(e)
            })?;
            container.delete(true)?;
        } else {
            let command_as_string = "ls -al";
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
        extract_base: dirs::home_dir()
            .unwrap()
            .join("oci-overlayer")
            .join("containers"),
        image_dir: dirs::home_dir()
            .unwrap()
            .join("oci-overlayer")
            .join("blobs"),
    };
    let ubuntu = "docker.io/library/ubuntu:latest";
    let fedora = "registry.fedoraproject.org/fedora:latest";
    let quay = "quay.io/drahnr/rust-glibc-builder";
    let busybox = "docker.io/library/busybox:latest";
    houdini.run(fedora).await?;
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
