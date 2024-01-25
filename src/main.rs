mod util;

mod errors;
use color_eyre::owo_colors::OwoColorize;
use errors::*;
use fs_err as fs;
use libcontainer::{
    container::builder::ContainerBuilder, syscall::syscall::SyscallType,
    workload::default::DefaultExecutor,
};

use oci_distribution::manifest::{
    IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
};
use oci_spec::runtime::{
    Linux, LinuxCapabilities, LinuxIdMapping, LinuxIdMappingBuilder, RootBuilder, Spec,
};
use std::{
    collections::VecDeque,
    io::Seek,
    os::unix::fs::{MetadataExt, PermissionsExt},
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
    let metadata = unpack_dest.metadata()?;
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
    fn ensure_parent_dir_exists(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let parent_dir = path
            .as_ref()
            .parent()
            .expect("Parent dir exists, otherwise this is unsafe. qed");
        ensure_dir_exists(parent_dir)
    }

    fn ensure_dir_exists(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        gum::trace!(target: LOG_TARGET, "Attempting to create parent dir {}", path.display());

        if let Err(e) = fs_err::create_dir_all(&path) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                gum::error!(target: LOG_TARGET, "Failed to create parent dir {}: {:?}", path.display(), e);
                Err(e)?
            }
            gum::trace!(target: LOG_TARGET, "Parent dir already exists {}, nothing to do", path.display());
        }
        Ok(())
    }
    let mut deferred = VecDeque::with_capacity(128);
    let mut permission_fixups = VecDeque::with_capacity(128);
    for entry in arch.entries()? {
        let mut entry = entry?;
        let in_tar_relative_path = entry.path()?.to_path_buf();
        let in_tar_relative_path = PathBuf::from_iter(in_tar_relative_path.components().skip(1));
        let unpack_file_dest = unpack_dest.join(&in_tar_relative_path);

        let Ok(mode) = entry.header().mode() else {
            gum::warn!(target: LOG_TARGET, "Missing mode, skipping unpack of {}", in_tar_relative_path.display());
            continue;
        };
        let uid = entry.header().uid()?;
        let gid = entry.header().gid()?;
        match entry.header().entry_type() {
            tar::EntryType::Regular => {
                gum::trace!(target: LOG_TARGET, "Unpacking  (1st round, regular files) {} to {}", in_tar_relative_path.display(), unpack_file_dest.display());
                ensure_parent_dir_exists(&unpack_file_dest)?;
                let mut dest_f = fs_err::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(unpack_file_dest)?;
                std::io::copy(&mut entry, &mut dest_f)?;
            }
            // symlinks can be dirs, if we create the files earlier and ensure parent dirs, we have to also create all parent symlinks
            et @ tar::EntryType::Symlink | et @ tar::EntryType::Link => {
                ensure_parent_dir_exists(&unpack_file_dest)?;

                let in_tar_link = entry.path()?.to_path_buf();
                let in_tar_original = entry.link_name()?.unwrap().to_path_buf();

                // link is always an abosolute path, that's what we need to create
                let link = unpack_dest.join(PathBuf::from_iter(in_tar_link.components().skip(1)));
                // original file can be _relative_ to the link path or absolute
                let original = if in_tar_original.starts_with("..") {
                    // relative, keep it
                    in_tar_original.clone()
                } else {
                    // FIXME TODO
                    // in the container, we might need a different target for symlinks
                    // since "/" has a different meaning. The following works for the _host_
                    // but for the container I don't know how the namespaces / cgroups handle symlink targets.
                    // There are _a lot_ of symlinks
                    unpack_dest.join(PathBuf::from_iter(in_tar_original.components().skip(1)))
                };
                if link == original {
                    gum::warn!(target: LOG_TARGET, "Contains self targeted link {}.", link.display().blue());
                    continue;
                }
                if et == tar::EntryType::Symlink {
                    gum::debug!(target: LOG_TARGET, "Creating symbolic link at {link} pointing to {orig}", link=link.display(), orig=original.display());
                    fs::soft_link(&original, &link)?;
                    permission_fixups.push_back((et, link.clone(), mode, uid, gid));
                } else {
                    gum::debug!(target: LOG_TARGET, "Creating hard link at {link} pointing to {orig}", link=link.display(), orig=original.display());
                    fs::hard_link(&original, &link)?;
                    permission_fixups.push_back((et, link.clone(), mode, uid, gid));
                }
                // symlinks don't work
            }
            _ => {
                deferred.push_back(entry);
            }
        }
    }

    for entry in deferred {
        let in_tar_relative_path_orig = entry.path()?.to_path_buf();
        let in_tar_relative_path =
            PathBuf::from_iter(in_tar_relative_path_orig.components().skip(1));
        let unpack_file_dest = unpack_dest.join(&in_tar_relative_path);
        if !entry.header().entry_type().is_file() {
            gum::trace!(target: LOG_TARGET, "Unpacking  (2nd round, non-regular files) {} to {}", in_tar_relative_path.display(), unpack_file_dest.display());
        }
        ensure_parent_dir_exists(&unpack_file_dest)?;

        let Ok(mode) = entry.header().mode() else {
            gum::warn!(target: LOG_TARGET, "Missing mode, skipping unpack of {}", in_tar_relative_path.display());
            continue;
        };
        let uid = entry.header().uid()?;
        let gid = entry.header().gid()?;
        match entry.header().entry_type() {
            et @ tar::EntryType::Directory => {
                ensure_dir_exists(&unpack_file_dest)?;
                // don't attempt to change the destination folder owner
                if unpack_file_dest != unpack_dest {
                    permission_fixups.push_back((et, unpack_file_dest, mode, uid, gid));
                }
            }
            et @ tar::EntryType::Regular => {
                permission_fixups.push_back((et, unpack_file_dest, mode, uid, gid));
            }
            et => {
                gum::debug!(target: LOG_TARGET, "{:?}, unhandled, skipping..", et);
            }
        }
    }

    gum::info!(target: LOG_TARGET, "Applying permissions..");

    let ignore_owner = true; // a regular owner cannot change ownership to i.e. root

    // deferred permissioning, avoids setting permissions on a dir that'd still have files yet to be unpacked
    for (et, path, mode, uid, gid) in permission_fixups {
        use std::os::unix::prelude::*;

        if !ignore_owner {
            gum::info!(target: LOG_TARGET, "Setin ownershop {uid}:{gid} and {mode:o} of {}", path.display());
            if !et.is_symlink() && !et.is_hard_link() {
                if let Err(e) = chown(&path, uid, gid) {
                    gum::error!(target: LOG_TARGET, "Failed to change owner: {e:?}");
                }
            }
        }

        let mode = mode & !mask;
        let perm = std::fs::Permissions::from_mode(mode as _);
        if let Err(e) = chmod(&path, perm) {
            gum::error!(target: LOG_TARGET, "Failed to set permissions ({:o}) for {} of type {:?}: {:?}", mode.red(), path.display(), et.yellow(), e);
        }
    }

    // TODO fixup permissions in a 3rd loop
    Ok(())
}

fn chown(path: &std::path::Path, uid: u64, gid: u64) -> std::io::Result<()> {
    use std::io;
    use std::os::unix::prelude::*;

    let uid: libc::uid_t = uid.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("UID {} is {} too large!", uid, path.display()),
        )
    })?;
    let gid: libc::gid_t = gid.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("GID {} for {} is too large!", gid, path.display()),
        )
    })?;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("path {} contains null character: {:?}", path.display(), e),
        )
    })?;

    unsafe {
        let ret = libc::lchown(cpath.as_ptr(), uid, gid);
        if ret != 0 {
            let e = io::Error::last_os_error();
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to set ownership {}:{} of {path} with code {code}: {e:?}",
                    uid,
                    gid,
                    code = ret,
                    path = path.display(),
                    e = e
                ),
            ))
        } else {
            Ok(())
        }
    }
}

fn chmod(path: &std::path::Path, perms: std::fs::Permissions) -> std::io::Result<()> {
    fs_err::set_permissions(&path, perms)
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
        gum::trace!(target: LOG_TARGET, "Unpacking {} to {}", in_tar_relative_path, unpack_file_dest.display());
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
            let layer_blob_path = layer_blob_dir.join(layer.digest.split(':').nth(1).unwrap());
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
                    == const_hex::decode(dbg!(&layer.digest.split(':').nth(1).unwrap())).unwrap()
            }) {
                gum::info!(target: LOG_TARGET, "Layer blob already exists on disk {}, skipping download", layer_blob_path.display());
            } else {
                let blob_file = fs_err::OpenOptions::new()
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
                    let arch = tar::Archive::new(&mut blob);
                    unpack(arch, &layer_blob_path, &unpack_dest)?;
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
                    let arch = tar::Archive::new(decompressed);
                    unpack(arch, &layer_blob_path, &unpack_dest)?;
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

        assert!(fs_err::metadata(root_dir)?.is_dir());

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
            let mut linux = Linux::rootless(1000, 1000);

            // linux.set_rootfs_propagation(Some("shared".to_owned()));

            let mut process = oci_spec::runtime::Process::default();
            process
                .set_env(Some(vec![
                    "PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/bin".to_owned(),
                ]))
                .set_cwd(PathBuf::from("/"))
                .set_args(Some(Vec::from_iter(
                    ["/usr/bin/bash", "-c", "ls"]
                        .into_iter()
                        .map(|x| x.to_owned()),
                )))
                .set_capabilities(Some(caps))
                .set_no_new_privileges(Some(true))
                .set_terminal(Some(true));
            // .set_user({ let mut user = User::default(); user.set_gid(0).set_uid(0); user});

            let root = RootBuilder::default()
                .path(root_dir)
                .readonly(true)
                .build()?;
            let mut lidmap = LinuxIdMappingBuilder::default()
                .host_id(1000_u32)
                .container_id(0_u32)
                .size(1_u32)
                .build()?;
            spec.set_linux(Some(linux))
                .set_mounts(Some(vec![]))
                .set_hostname("trapped".to_owned().into())
                .set_root(Some(root))
                .set_hooks(None)
                .set_annotations(None)
                .set_process(Some(process))
                .set_uid_mappings(Some(vec![lidmap]));
            gum::info!(target: LOG_TARGET, "Spec {spec:?}");

            // not sure this is required?
            // if it's enabled, get duplicate symlink errors
            // let mut rootfs = libcontainer::rootfs::RootFS::new();
            // rootfs.prepare_rootfs(&spec, &root_dir, true, true)?;

            let config_json = serde_json::to_string_pretty(&spec).unwrap();
            fs_err::write(bundle_dir.join("config.json"), config_json.as_bytes()).unwrap();

            let container = ContainerBuilder::new(
                container_id.as_hyphenated().to_string(),
                SyscallType::default(),
            );
            let container_state_dir = self.extract_base.join("container-state"); // auto suffixed by the container id
            fs_err::create_dir_all(&container_state_dir)?;
            let mut container = container
                .with_executor(DefaultExecutor {})
                .with_root_path(&container_state_dir)?
                .validate_id()?
                .as_init(bundle_dir)
                .with_detach(false)
                .with_systemd(false)
                .build()?;
            gum::info!("Container {container_id:?} torn down, pending deletion.");
            container.start().map_err(|e| {
                let _ = dbg!(container.delete(true));
                e
            })?;
            container.delete(true)?;
        } else {
            let command_as_string = "ls -al";
            gum::info!(target: LOG_TARGET, "Attempting to run `sh -c {}` in {}", command_as_string, root_dir.display());
            let mut command = std::process::Command::new("sh");
            command.arg("-c");
            command.args(command_as_string.split(' '));
            command.current_dir(root_dir);
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
    let _ubuntu = "docker.io/library/ubuntu:latest";
    let fedora = "registry.fedoraproject.org/fedora:latest";
    let _quay = "quay.io/drahnr/rust-glibc-builder";
    let _busybox = "docker.io/library/busybox:latest";
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
