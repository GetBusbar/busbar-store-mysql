# SPDX-License-Identifier: Apache-2.0
#
# RENDERED by `busbar-release plugin heal` from GetBusbar/busbar-release template/conformance/tools.sh;
# a hand edit is overwritten by the next sync.
#
# Sourced by testing/conformance/run.sh: `. testing/conformance/tools.sh rust node`. Puts each named
# tool on PATH at the version pinned here. ModernCI compute has no node and no package manager, so the
# conformance instruments bring their own: the official release asset, fetched with curl, checked
# against the sha256 pinned here BEFORE it is unpacked, and cached under
# ${MODERNCI_CACHE_DIR:-$HOME/.cache}/conformance-tools/. A tool already on PATH at the pinned major is
# used as is. A platform with no pin, a failed download or a sha mismatch is a refusal (return 1),
# never a fall-back. Managed cache versions keep the current pins, two recent inactive installs
# and every leased install. Unmanaged legacy entries are preserved for compatibility with active
# older drivers; no process is assumed idle merely because its cache files are old. An instrument that needs system libraries (a browser, a JVM suite) runs in a
# docker image pinned by digest in the suite's own script, not here.
#
#   rust  rustup 1.28.2 (sha-pinned rustup-init) installing what rust-toolchain.toml names; cargo
#         already on PATH is left alone
#   node  node v22.23.3 (nodejs.org)

_ct_root="${MODERNCI_CACHE_DIR:-${HOME:+$HOME/.cache}}"
[ -n "$_ct_root" ] || { echo "tools.sh: no cache root; set MODERNCI_CACHE_DIR or HOME" >&2; return 1; }
_ct_root="$_ct_root/conformance-tools"
_ct_node_ver=v22.23.3
_ct_node_major="${_ct_node_ver#v}"; _ct_node_major="${_ct_node_major%%.*}"
_ct_rustup_ver=1.28.2

# Seal verified-download executable bytes before publication, and recheck before every reuse.
# System tools outside this cache retain the explicit PATH trust policy described above.
_ct_integrity() {
  python3 -I - "$1" "$2" "$3" <<'PYINTEGRITY'
import hashlib, json, pathlib, sys
mode, directory, probe = sys.argv[1:4]
root = pathlib.Path(directory)
try:
    executable = (root / probe).resolve(strict=True)
    if not executable.is_relative_to(root.resolve()):
        raise ValueError("executable escapes the installation")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    record = {"probe": probe, "sha256": digest}
    path = root / ".busbar-tool.json"
    if mode == "seal":
        path.write_text(json.dumps(record) + "\n")
    elif json.loads(path.read_text()) != record:
        raise ValueError("cached executable bytes differ from the verified installation")
except (OSError, ValueError) as error:
    print(f"tools.sh: cached tool integrity refused: {error}", file=sys.stderr)
    sys.exit(1)
PYINTEGRITY
}

# Managed versions hold this shared lease for the sourcing shell's lifetime. Existing caches
# without a lease marker remain unmanaged: an older driver may still be using those paths.
_ct_cache_lease() {
  local key="$1" lease mode=shared held
  # Bash 3.2 (the macOS system shell) has no dynamic descriptor allocation. One descriptor
  # per tool remains open for the driver's lifetime; changing PATH replaces the old tool lease.
  case "$key" in
    node-*) _ct_cache_fd=8; held=_ct_node_cache_key ;;
    rustup-*) _ct_cache_fd=9; held=_ct_rustup_cache_key ;;
    *) echo "tools.sh: unknown cache lease key" >&2; return 1 ;;
  esac
  [ "${!held-}" != "$key" ] || return 0
  lease="$_ct_root/.leases/$key.lock"
  if [ ! -f "$lease" ] && [ -e "$_ct_root/$key" ]; then
    # A separate marker protects migration without claiming ownership of a legacy install.
    lease="$_ct_root/.leases/legacy-$key.lock"
    [ -f "$_ct_root/$key/.busbar-tool.json" ] || mode=exclusive
  fi
  mkdir -p "$_ct_root/.leases" || return 1
  case "$_ct_cache_fd" in
    8) exec 8>"$lease" || return 1 ;;
    9) exec 9>"$lease" || return 1 ;;
  esac
  python3 -I -c 'import fcntl,sys; fcntl.flock(int(sys.argv[1]), fcntl.LOCK_EX if sys.argv[2] == "exclusive" else fcntl.LOCK_SH)' "$_ct_cache_fd" "$mode" || return 1
  printf -v "$held" '%s' "$key"
}

# Protect a managed tool already inherited on PATH before considering any cache deletion.
_ct_path_lease() {
  local path key
  path="$(command -v "$1" 2>/dev/null)" || return 0
  case "$path" in
    "$_ct_root"/*)
      key="${path#"$_ct_root"/}"; key="${key%%/*}"
      _ct_cache_lease "$key" || return 1
      # Unsealed legacy bytes are never executed to query their version. Provisioning obtains
      # the pinned official asset and compares it before adding integrity metadata.
      [ ! -f "$_ct_root/$key/.busbar-tool.json" ] || _ct_integrity check "$_ct_root/$key" "${path#"$_ct_root/$key"/}"
      ;;
  esac
}

# Keep current versions, two recent inactive installations per tool, and every active lease.
# Lease files remain stable so opening a lease can never race with replacing its lock inode.
_ct_prune() {
  _ct_scratch_prune || return 1
  python3 -I - "$_ct_root" "$_ct_node_ver" "$_ct_rustup_ver" <<'PYCACHE'
import fcntl, os, pathlib, re, shutil, sys
root = pathlib.Path(sys.argv[1])
current_node, current_rustup = sys.argv[2:4]
leases = root / ".leases"
if not leases.is_dir():
    sys.exit(0)
patterns = {"node": r"node-v[0-9]+\.[0-9]+\.[0-9]+-(?:linux|darwin)-(?:x64|arm64)",
            "rustup": r"rustup-[0-9]+\.[0-9]+\.[0-9]+"}
try:
    for family, pattern in patterns.items():
        inactive = 0
        markers = sorted(leases.glob("*.lock"), key=lambda p: p.stat().st_mtime, reverse=True)
        for marker in markers:
            key = marker.name[:-5]
            if re.fullmatch(pattern, key) is None:
                continue
            dest = root / key
            archives = [root / (key + ".tar.gz"), *root.glob(key + ".tar.gz.part.*")] if family == "node" else list(root.glob("rustup-init-" + key[7:] + "-*"))
            if not dest.exists() and not any(p.exists() for p in archives):
                continue
            with marker.open("a") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                probe = dest / ("bin/node" if family == "node" else "cargo/bin/cargo")
                for archive in archives:
                    if ".part." in archive.name or (os.access(probe, os.X_OK) and (dest / ".busbar-tool.json").is_file()):
                        archive.unlink(missing_ok=True)
                current = key.startswith("node-" + current_node + "-") if family == "node" else key == "rustup-" + current_rustup
                if current:
                    continue
                inactive += 1
                if inactive > 2:
                    if dest.is_symlink():
                        dest.unlink()
                    elif dest.exists():
                        shutil.rmtree(dest)
                    for archive in archives:
                        archive.unlink(missing_ok=True)
except OSError as error:
    print(f"tools.sh: cannot prune managed cache: {error}", file=sys.stderr)
    sys.exit(1)
PYCACHE
}

# Scratch creation and reaping share a stable namespace lock. Descriptor 6 holds the
# operation lease until its shell and every inherited child have exited, including SIGKILL.
# No PID or file age is used to infer whether work is abandoned.
_ct_scratch_start() {
  mkdir -p "$_ct_root/.scratch" || return 1
  exec 5>"$_ct_root/.scratch/.lock" || return 1
  python3 -I -c 'import fcntl; fcntl.flock(5, fcntl.LOCK_EX)' || return 1
  _ct_work="$(mktemp -d "$_ct_root/.scratch/run.XXXXXX")" || return 1
  exec 6>"$_ct_work/.lease" || return 1
  python3 -I -c 'import fcntl; fcntl.flock(6, fcntl.LOCK_EX)' || return 1
  python3 -I -c 'import fcntl; fcntl.flock(5, fcntl.LOCK_UN)' || return 1
  exec 5>&-
  trap 'rm -rf "$_ct_work"' EXIT
  trap 'exit 1' HUP INT TERM
}

_ct_scratch_prune() {
  python3 -I - "$_ct_root/.scratch" <<'PYSCRATCH'
import fcntl, os, pathlib, re, shutil, sys
root = pathlib.Path(sys.argv[1])
if not root.is_dir():
    sys.exit(0)
try:
    with (root / ".lock").open("a") as namespace:
        fcntl.flock(namespace, fcntl.LOCK_EX)
        for entry in root.iterdir():
            if re.fullmatch(r"run\.[A-Za-z0-9]{6}", entry.name) is None or entry.is_symlink() or not entry.is_dir():
                continue
            marker = entry / ".lease"
            if marker.is_symlink() or not marker.is_file():
                continue
            with marker.open("r+") as lease:
                try:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                shutil.rmtree(entry)
except OSError as error:
    print(f"tools.sh: cannot prune managed scratch: {error}", file=sys.stderr)
    sys.exit(1)
PYSCRATCH
}

_ct_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# _ct_fetch <url> <sha256> <dest>: the asset at dest, verified, or return 1.
_ct_fetch() (
  [ -f "$3" ] && [ "$(_ct_sha256 "$3")" = "$2" ] && exit 0
  mkdir -p "$(dirname "$3")" || exit 1
  _ct_scratch_start || exit 1
  part="$_ct_work/download"
  curl -fsSL --retry 3 --retry-max-time 660 --max-time 600 --max-filesize 536870912 --connect-timeout 30 --speed-limit 1024 --speed-time 60 -o "$part" "$1" || { echo "tools.sh: download failed" >&2; exit 1; }
  got="$(_ct_sha256 "$part")"
  [ "$got" = "$2" ] || { echo "tools.sh: sha256 mismatch: expected $2, got $got" >&2; exit 1; }
  mv "$part" "$3"
)

# _ct_publish <staged dir> <dir> <probe>: move a fully staged install into place in one rename; true
# only when <dir>/<probe> is executable after it. Concurrent runs share the cache: a run that finds
# <dir> never sees it half written, and the loser of a race drops its own copy and uses the winner's.
# A <dir> without its probe (an install interrupted before staging existed) is moved aside and
# replaced, never used.
_ct_publish() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import fcntl, hashlib, json, os, pathlib, shutil, sys, tempfile
stage, dest, probe = sys.argv[1:4]
done = lambda: os.access(os.path.join(dest, probe), os.X_OK)
try:
    with open(dest + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not done():
            if os.path.lexists(dest):
                if os.path.islink(dest):
                    os.unlink(dest)
                else:
                    shutil.rmtree(dest)
            os.rename(stage, dest)
        if not done():
            raise OSError("published tool has no executable probe")
        known = pathlib.Path(stage) / ".busbar-tool.json"
        metadata = pathlib.Path(dest) / ".busbar-tool.json"
        if known.is_file() and not metadata.exists():
            expected = json.loads(known.read_text())
            executable = (pathlib.Path(dest) / probe).resolve(strict=True)
            if not executable.is_relative_to(pathlib.Path(dest).resolve()):
                raise ValueError("legacy executable escapes its installation")
            actual = {"probe": probe, "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
            if actual != expected:
                raise ValueError("legacy executable differs from the pinned official asset")
            with tempfile.NamedTemporaryFile(mode="w", dir=dest, prefix=".integrity-", delete=False) as record:
                record.write(json.dumps(expected) + "\n")
            os.replace(record.name, metadata)
except (OSError, ValueError) as error:
    print(f"tools.sh: cannot publish {dest}: {error}", file=sys.stderr)
    sys.exit(1)
finally:
    shutil.rmtree(stage, ignore_errors=True)
PY
}

_ct_plat() { # <os>-<arch> as nodejs.org names them
  local os arch
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) return 1 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) return 1 ;; esac
  echo "$os-$arch"
}

_ct_node() {
  local have plat sha dir
  local existing key
  existing="$(command -v node 2>/dev/null || true)"
  have=0
  case "$existing" in
    "$_ct_root"/*)
      key="${existing#"$_ct_root"/}"; key="${key%%/*}"
      if [ -f "$_ct_root/$key/.busbar-tool.json" ]; then
        have="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
      fi
      ;;
    *) have="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" ;;
  esac
  [ "$have" = "$_ct_node_major" ] && return 0
  plat="$(_ct_plat)" || { echo "tools.sh: no pinned node for $(uname -s)-$(uname -m)" >&2; return 1; }
  case "$plat" in
    linux-x64)    sha=1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af ;;
    linux-arm64)  sha=5ced2d48d1d7198739b7f86804de0171aefb6823b684b12341d3321afc3cb0b2 ;;
    darwin-x64)   sha=8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8 ;;
    darwin-arm64) sha=23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53 ;;
    *) echo "tools.sh: no pinned node for $plat" >&2; return 1 ;;
  esac
  dir="$_ct_root/node-$_ct_node_ver-$plat"
  _ct_cache_lease "node-$_ct_node_ver-$plat" || return 1
  if [ ! -x "$dir/bin/node" ] || [ ! -f "$dir/.busbar-tool.json" ]; then
    _ct_fetch "https://nodejs.org/dist/$_ct_node_ver/node-$_ct_node_ver-$plat.tar.gz" "$sha" "$_ct_root/node-$_ct_node_ver-$plat.tar.gz" || return 1
    (
      _ct_scratch_start || exit 1
      stage="$_ct_work/node"
      mkdir "$stage" || exit 1
      tar -xzf "$_ct_root/node-$_ct_node_ver-$plat.tar.gz" -C "$stage" || exit 1
      _ct_integrity seal "$stage/node-$_ct_node_ver-$plat" bin/node || exit 1
      _ct_publish "$stage/node-$_ct_node_ver-$plat" "$dir" bin/node
    ) || return 1
  fi
  _ct_integrity check "$dir" bin/node || return 1
  python3 -I -c 'import fcntl,sys; fcntl.flock(int(sys.argv[1]), fcntl.LOCK_SH)' "$_ct_cache_fd" || return 1
  PATH="$dir/bin:$PATH"; export PATH
}

_ct_rust() {
  [ -f rust-toolchain.toml ] || [ -f rust-toolchain ] || { echo "tools.sh: no pinned Rust toolchain" >&2; return 1; }
  local existing key
  existing="$(command -v cargo 2>/dev/null)" && {
    case "$existing" in
      "$_ct_root"/*)
        key="${existing#"$_ct_root"/}"; key="${key%%/*}"
        [ ! -f "$_ct_root/$key/.busbar-tool.json" ] || return 0
        ;;
      *) return 0 ;;
    esac
  }
  local t sha
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  t=x86_64-unknown-linux-gnu;  sha=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;;
    Linux-aarch64) t=aarch64-unknown-linux-gnu; sha=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;;
    Darwin-x86_64) t=x86_64-apple-darwin;      sha=9c331076f62b4d0edeae63d9d1c9442d5fe39b37b05025ec8d41c5ed35486496 ;;
    Darwin-arm64)  t=aarch64-apple-darwin;      sha=20ef5516c31b1ac2290084199ba77dbbcaa1406c45c1d978ca68558ef5964ef5 ;;
    *) echo "tools.sh: no pinned rustup for $(uname -s)-$(uname -m)" >&2; return 1 ;;
  esac
  local home="$_ct_root/rustup-$_ct_rustup_ver"
  _ct_cache_lease "rustup-$_ct_rustup_ver" || return 1
  RUSTUP_HOME="$home/rustup"; CARGO_HOME="$home/cargo"
  export RUSTUP_HOME CARGO_HOME
  if [ ! -x "$CARGO_HOME/bin/cargo" ] || [ ! -f "$home/.busbar-tool.json" ]; then
    _ct_fetch "https://static.rust-lang.org/rustup/archive/$_ct_rustup_ver/$t/rustup-init" "$sha" "$_ct_root/rustup-init-$_ct_rustup_ver-$t" || return 1
    chmod +x "$_ct_root/rustup-init-$_ct_rustup_ver-$t" || { echo "tools.sh: cannot make rustup installer executable" >&2; return 1; }
    (
      _ct_scratch_start || exit 1
      stage="$_ct_work/rustup"
      mkdir "$stage" || exit 1
      RUSTUP_HOME="$stage/rustup" CARGO_HOME="$stage/cargo" "$_ct_root/rustup-init-$_ct_rustup_ver-$t" -y --no-modify-path --default-toolchain none || exit 1
      _ct_integrity seal "$stage" cargo/bin/cargo || exit 1
      _ct_publish "$stage" "$home" cargo/bin/cargo
    ) || return 1
  fi
  _ct_integrity check "$home" cargo/bin/cargo || return 1
  python3 -I -c 'import fcntl,sys; fcntl.flock(int(sys.argv[1]), fcntl.LOCK_SH)' "$_ct_cache_fd" || return 1
  PATH="$CARGO_HOME/bin:$PATH"; export PATH
  python3 -I - "$home/toolchain.lock" <<'PY'
import fcntl, subprocess, sys
with open(sys.argv[1], "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    ready = subprocess.run(["rustup", "show", "active-toolchain"], stdout=subprocess.DEVNULL)
    if ready.returncode:
        sys.exit(subprocess.call(["rustup", "toolchain", "install"]))
PY
}

for _ct_t in "$@"; do
  case "$_ct_t" in rust) _ct_path_lease cargo || return 1 ;; node) _ct_path_lease node || return 1 ;; esac
  _ct_prune || return 1
  case "$_ct_t" in
    rust) _ct_rust || return 1 ;;
    node) _ct_node || return 1 ;;
    *) echo "tools.sh: unknown tool '$_ct_t' (known: rust node)" >&2; return 1 ;;
  esac
done
