//! The container side of the interop suite: every peer is an image built from a Dockerfile in
//! `tests/interop/<peer>/`, started through testcontainers and removed when its test ends.
//!
//! What it guarantees, because each is a way an oracle can quietly stop being one:
//!
//! * no Docker is a skip **by name**, and a failure under `IEC61850_REQUIRE_INTEROP=1`;
//! * an image that does not build is always a failure, never a skip;
//! * a container lives exactly as long as the value that owns it, panics included;
//! * a peer client reaches this crate's server at `host.docker.internal`, and that server never
//!   listens on an address the LAN can reach;
//! * no container is privileged, uses the host network or sees the Docker socket.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use testcontainers::core::{AccessMode, BuildImageOptions, CmdWaitFor, ExecCommand, Host, IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::{SyncBuilder, SyncRunner};
use testcontainers::{Container, ContainerRequest, GenericBuildableImage, GenericImage, ImageExt};

/// The name a peer client uses for the host this suite runs on.
pub const HOST: &str = "host.docker.internal";

/// Whether a skip is a failure. CI sets it: an oracle that can quietly stop running is not one.
pub fn required() -> bool {
    std::env::var("IEC61850_REQUIRE_INTEROP").is_ok_and(|v| v != "0")
}

/// Whether Docker answers. `false` means the caller skips, which this function has already said
/// by name — or it panics, if a skip is not allowed.
pub fn docker() -> bool {
    static UP: OnceLock<bool> = OnceLock::new();
    // A job that runs the peers elsewhere opts out explicitly, and says so; it never
    // combines with `IEC61850_REQUIRE_INTEROP`.
    if std::env::var("IEC61850_SKIP_INTEROP").is_ok_and(|v| v != "0") {
        assert!(!required(), "IEC61850_SKIP_INTEROP and IEC61850_REQUIRE_INTEROP are both set");
        eprintln!("skipping: IEC61850_SKIP_INTEROP is set");
        return false;
    }
    let up = *UP.get_or_init(|| Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]).output().is_ok_and(|o| o.status.success()));
    if !up {
        assert!(!required(), "IEC61850_REQUIRE_INTEROP is set, but Docker is not available");
        eprintln!("skipping: docker unavailable");
    }
    up
}

/// The address this crate's server binds for a peer client: loopback on Docker Desktop, which
/// forwards `host.docker.internal` there, and the default bridge's gateway on Linux, which is
/// where `host-gateway` points. Never all interfaces. `IEC61850_INTEROP_BIND` overrides it.
pub fn bind_addr() -> IpAddr {
    static ADDR: OnceLock<IpAddr> = OnceLock::new();
    *ADDR.get_or_init(|| {
        if let Some(addr) = std::env::var("IEC61850_INTEROP_BIND").ok().and_then(|a| a.parse().ok()) {
            return addr;
        }
        if !cfg!(target_os = "linux") {
            return IpAddr::V4(Ipv4Addr::LOCALHOST);
        }
        let out = Command::new("docker")
            .args(["network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"])
            .output()
            .expect("docker network inspect bridge");
        String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or_else(|e| panic!("the bridge gateway: {e}"))
    })
}

/// The directory of one peer's build context.
fn context(peer: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop").join(peer)
}

/// Every file under `dir`, relative to it, sorted.
fn files(dir: &Path) -> Vec<PathBuf> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(at).unwrap_or_else(|e| panic!("{}: {e}", at.display())).flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(root, &path, out);
            } else {
                out.push(path.strip_prefix(root).expect("under root").to_path_buf());
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// FNV-1a over the context, so editing a Dockerfile or a probe rebuilds its image.
fn digest(dir: &Path, files: &[PathBuf]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for f in files {
        for b in f.to_string_lossy().bytes().chain(std::fs::read(dir.join(f)).expect("read context file")) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// The image of one peer, built from `tests/interop/<peer>/` the first time it is asked for and
/// cached by Docker after that. A build that fails fails the test.
pub fn image(peer: &str) -> GenericImage {
    static BUILDS: OnceLock<Mutex<BTreeMap<String, (String, String)>>> = OnceLock::new();
    let mut built = BUILDS.get_or_init(Mutex::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (name, tag) = built
        .entry(peer.to_string())
        .or_insert_with(|| {
            let dir = context(peer);
            let list = files(&dir);
            let (name, tag) = (format!("iec61850-interop-{peer}"), digest(&dir, &list));
            let mut build = GenericBuildableImage::new(name.clone(), tag.clone());
            for f in &list {
                build = build.with_file(dir.join(f), f.to_string_lossy().into_owned());
            }
            let started = Instant::now();
            let _image =
                build.build_image_with(BuildImageOptions::new().with_skip_if_exists(true)).unwrap_or_else(|e| panic!("the {peer} image did not build: {e}"));
            eprintln!("image {name}:{tag} ready in {:.1}s", started.elapsed().as_secs_f32());
            (name, tag)
        })
        .clone();
    GenericImage::new(name, tag)
}

/// A peer container that idles, so its tools run through [`exec`], and whose clients reach this
/// crate's server at [`HOST`].
pub fn client_container(peer: &str) -> Container<GenericImage> {
    image(peer).with_entrypoint("sleep").with_cmd(["infinity"]).with_host(HOST, Host::HostGateway).start().unwrap_or_else(|e| panic!("start {peer}: {e}"))
}

/// A peer container running `cmd` with `port` mapped to the host, `files` copied in first and,
/// when `ready` is given, started once that line is on its standard output. Returns the
/// container and the host address that reaches the port.
pub fn server_container(peer: &str, port: u16, cmd: &[&str], files: &[(&str, &str)], ready: Option<&str>) -> (Container<GenericImage>, SocketAddr) {
    let mut image = image(peer).with_exposed_port(port.tcp());
    if let Some(line) = ready {
        image = image.with_wait_for(WaitFor::message_on_stdout(line));
    }
    let mut request = image.with_cmd(cmd.iter().copied()).with_startup_timeout(Duration::from_secs(60));
    for (path, text) in files {
        request = request.with_copy_to((*path).to_string(), text.as_bytes().to_vec());
    }
    let container = request.start().unwrap_or_else(|e| panic!("start {peer}: {e}"));
    let mapped = container.get_host_port_ipv4(port.tcp()).expect("the mapped port");
    (container, SocketAddr::from((Ipv4Addr::LOCALHOST, mapped)))
}

/// Run `argv` in `container` to completion: its standard output, standard error and exit code.
pub fn exec(container: &Container<GenericImage>, argv: &[&str]) -> (String, String, i64) {
    let mut res = container
        .exec(ExecCommand::new(argv.iter().map(|s| (*s).to_string())).with_cmd_ready_condition(CmdWaitFor::exit()))
        .unwrap_or_else(|e| panic!("exec {argv:?}: {e}"));
    let out = String::from_utf8_lossy(&res.stdout_to_vec().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(&res.stderr_to_vec().unwrap_or_default()).into_owned();
    (out, err, res.exit_code().ok().flatten().unwrap_or(-1))
}

/// Run a shell command line in `container`.
pub fn sh(container: &Container<GenericImage>, line: &str) -> (String, String, i64) {
    exec(container, &["sh", "-c", line])
}

/// A file out of a container, as text.
pub fn read_file(container: &Container<GenericImage>, path: &str) -> String {
    let (out, err, code) = exec(container, &["cat", path]);
    assert_eq!(code, 0, "{path}: {err}");
    out
}

/// `f` until it returns `Some`, or panic with `what` at the deadline. Docker's port proxy accepts a
/// TCP connection before the peer listens, so "connected" is not "ready".
pub fn retry<T>(what: &str, deadline: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let until = Instant::now() + deadline;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < until, "{what}: not ready after {deadline:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A user-defined Docker network for one process-bus test: removed when dropped.
pub struct Network(pub String);

impl Network {
    pub fn new(test: &str) -> Network {
        let name = format!("iec61850-pb-{}-{test}", std::process::id());
        let out = Command::new("docker").args(["network", "create", &name]).output().expect("docker network create");
        assert!(out.status.success(), "docker network create {name}: {}", String::from_utf8_lossy(&out.stderr));
        Network(name)
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", &self.0]).output();
    }
}

/// A container on `net` that may open a raw socket — `NET_RAW` and `NET_ADMIN` only, never
/// privileged and never the host's network.
pub fn on_network(request: impl Into<ContainerRequest<GenericImage>>, net: &Network, name: &str) -> Container<GenericImage> {
    let request: ContainerRequest<GenericImage> = request.into();
    request
        .with_network(net.0.clone())
        .with_container_name(format!("{}-{name}", net.0))
        .with_cap_add("NET_RAW")
        .with_cap_add("NET_ADMIN")
        .start()
        .unwrap_or_else(|e| panic!("start {name} on {}: {e}", net.0))
}

/// The container this crate's `ied` runs in on the process bus: the repository and `rawether`
/// mounted read-only, the build cached in named volumes, the binary built on first use.
pub fn ied_container(net: &Network, files: &[(&str, &str)]) -> Container<GenericImage> {
    // One build at a time: the cargo cache is a shared volume, and two unpacks into it race.
    static BUILD: Mutex<()> = Mutex::new(());
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize().expect("repository");
    let rawether = repo.join("../rawether").canonicalize().expect("rawether next to the repository");
    let mut request = image("ied")
        .with_mount(Mount::bind_mount(repo.to_string_lossy(), "/src/iec61850-rs").with_access_mode(AccessMode::ReadOnly))
        .with_mount(Mount::bind_mount(rawether.to_string_lossy(), "/src/rawether").with_access_mode(AccessMode::ReadOnly))
        .with_mount(Mount::volume_mount("iec61850-interop-cargo", "/usr/local/cargo/registry"))
        .with_mount(Mount::volume_mount("iec61850-interop-target", "/target"));
    for (path, text) in files {
        request = request.with_copy_to((*path).to_string(), text.as_bytes().to_vec());
    }
    let c = on_network(request, net, "ied");
    let _one = BUILD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Instant::now();
    let (out, _, code) = exec(&c, &["bash", "-c", "set -o pipefail; cd /src/iec61850-rs && cargo build --locked --features cli --bin ied 2>&1 | tail -20"]);
    assert_eq!(code, 0, "building ied for Linux failed:\n{out}");
    eprintln!("ied built for Linux in {:.1}s", started.elapsed().as_secs_f32());
    c
}
