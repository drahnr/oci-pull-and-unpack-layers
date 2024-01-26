use super::*;

// TODO: split it up
#[allow(missing_docs)]
#[fatality::fatality(splitable)]
pub enum Error {
    #[fatal]
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Failed to run command without container runtime")]
    NoContainerCommandExecutionFailed,

    #[error("Failed to build image with Podman")]
    PodmanBuildImageFailed,

    #[error("Failed to pull image with Podman")]
    PodmanPullImageFailed,

    #[error("Failed to load tar image with Podman")]
    PodmanLoadTarImageFailed,

    #[error("Failed to save tar image with Podman: {0}")]
    PodmanSaveTarImageFailed(String),

    #[error("Something went wrong while parsing PodmanCommand output:`{0}`")]
    PodmanCommandOutputParsing(String),

    #[error("Something went wrong while parsing image name from Podman output.")]
    PodmanCommandOutputParsingImageName,

    #[error("Something went wrong while parsing image SHA from Podman output.")]
    PodmanCommandOutputParsingImageSha,

    #[error("Something went wrong while converting path to string")]
    PathConversion,

    #[error("Image ID is incomplete")]
    IncompleteImageId { wannabe_id: String },

    #[error("Given path \"{p}\" isn't a file", p = .0.display())]
    TarNotFound(PathBuf),

    #[error("Container command is empty string.")]
    NoContainerCommand,

    // TODO: Split off errors
    #[error(transparent)]
    RootfsError(#[from] libcontainer::rootfs::RootfsError),
    #[error(transparent)]
    InvalidId(#[from] libcontainer::error::ErrInvalidID),
    #[error(transparent)]
    MissingSpec(#[from] libcontainer::error::MissingSpecError),
    #[error(transparent)]
    LibContainer(#[from] libcontainer::error::LibcontainerError),
    #[error(transparent)]
    InvalidSpec(#[from] libcontainer::error::ErrInvalidSpec),
    #[error(transparent)]
    OciSpec(#[from] oci_spec::OciSpecError),

    #[error(transparent)]
    RegistryResponse(#[from] oci_distribution::errors::OciDistributionError),
}
