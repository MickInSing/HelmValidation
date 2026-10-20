"""Load a chart straight from a Git repository web address.

Accepts what people paste from the browser:
  https://github.com/org/repo
  https://github.com/org/repo/tree/<ref>/<path/to/chart>
  https://gitlab.com/group/sub/repo/-/tree/<ref>/<path>
  https://bitbucket.org/org/repo/src/<ref>/<path>
  https://github.example.com/org/repo.git          (any https clone URL on an allowed host)

Safety: https only, host allow-list, shallow clone, timeout, size cap, no prompts,
symlinks checked out as plain files, tokens passed via env (never argv or logs).
"""
import base64
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path


class GitError(Exception):
    pass


ALLOWED_HOSTS = [h.strip().lower() for h in os.environ.get(
    "GIT_ALLOWED_HOSTS", "github.com,gitlab.com,bitbucket.org").split(",") if h.strip()]
GIT_TIMEOUT = int(os.environ.get("GIT_TIMEOUT", "60"))
GIT_MAX_MB = int(os.environ.get("GIT_MAX_MB", "200"))
CACHE_TTL = int(os.environ.get("GIT_CACHE_TTL", "900"))
CACHE_MAX = 6
SERVER_TOKEN = os.environ.get("GIT_TOKEN", "")

_cache = {}   # (clone_url, ref) -> dict(dir, commit, ref, t)
_lock = threading.Lock()


def host_allowed(host):
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS) or "*" in ALLOWED_HOSTS


def parse_url(url, ref="", path=""):
    """Web address -> (clone_url, ref, subpath, display)."""
    url = (url or "").strip()
    if not url:
        raise GitError("enter a Git repository address")
    if url.startswith("git@"):
        raise GitError("SSH addresses aren't supported. Use the https:// address from the browser")
    u = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    if u.scheme != "https":
        raise GitError("only https:// addresses are supported")
    if u.username or u.password:
        raise GitError("don't put credentials in the address. Use the token field instead")
    if not host_allowed(u.hostname):
        raise GitError(f"host '{u.hostname}' isn't allowed. Allowed: {', '.join(ALLOWED_HOSTS)} (set GIT_ALLOWED_HOSTS)")
    parts = [p for p in u.path.split("/") if p]
    url_ref, url_path = "", ""
    host = u.hostname.lower()

    if "-" in parts:                                      # GitLab: group/sub/repo/-/tree/ref/path
        i = parts.index("-")
        repo_parts, rest = parts[:i], parts[i + 1:]
        if rest and rest[0] in ("tree", "blob"):
            url_ref, url_path = (rest[1] if len(rest) > 1 else ""), "/".join(rest[2:])
    elif "bitbucket" in host and "src" in parts[2:3]:     # Bitbucket: org/repo/src/ref/path
        repo_parts, rest = parts[:2], parts[3:]
        url_ref, url_path = (rest[0] if rest else ""), "/".join(rest[1:])
    elif len(parts) >= 4 and parts[2] in ("tree", "blob"):  # GitHub (and GHE): org/repo/tree/ref/path
        repo_parts = parts[:2]
        url_ref, url_path = parts[3], "/".join(parts[4:])
    else:
        repo_parts = parts
    if len(repo_parts) < 2:
        raise GitError("that doesn't look like a repository address (expected host/owner/repo)")
    if url_path.endswith(("Chart.yaml", "values.yaml")) or re.search(r"\.ya?ml$", url_path):
        url_path = url_path.rsplit("/", 1)[0] if "/" in url_path else ""   # pasted a file: use its folder
    repo = "/".join(repo_parts)
    repo = repo[:-4] if repo.endswith(".git") else repo
    clone = f"https://{u.netloc}/{repo}.git"
    ref = (ref or url_ref).strip()
    path = (path if path else url_path).strip().strip("/")
    for v, what in ((ref, "branch/tag"), (path, "path")):
        if v and (".." in v.split("/") or v.startswith("-") or re.search(r"[\s\\~^:?*\[]", v)):
            raise GitError(f"invalid {what}: {v}")
    return clone, ref, path, f"{u.netloc}/{repo}"


def _env(token):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp",
           "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_LFS_SKIP_SMUDGE": "1"}
    cfg = [("core.symlinks", "false"), ("protocol.file.allow", "never"), ("core.hooksPath", "/dev/null")]
    token = token or SERVER_TOKEN
    if token:  # works for GitHub, GitLab and Bitbucket app passwords/PATs
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cfg.append(("http.extraHeader", f"Authorization: Basic {basic}"))
    env["GIT_CONFIG_COUNT"] = str(len(cfg))
    for i, (k, v) in enumerate(cfg):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    return env


def _git(args, cwd, env):
    try:
        p = subprocess.run(["git"] + args, cwd=cwd, env=env, capture_output=True, text=True, timeout=GIT_TIMEOUT)
    except FileNotFoundError:
        raise GitError("git isn't installed in this container")
    except subprocess.TimeoutExpired:
        raise GitError(f"git timed out after {GIT_TIMEOUT}s (repository too big or unreachable?)")
    if p.returncode != 0:
        msg = re.sub(r"Authorization: Basic \S+", "Authorization: ***", (p.stderr or p.stdout).strip())
        if re.search(r"Authentication failed|could not read Username|403|401|not found", msg, re.I):
            msg += "\n\nIf the repository is private, add a token (read access) and try again."
        raise GitError(msg[-800:])
    return p.stdout.strip()


def _du(path):
    total = 0
    for root, _, fs in os.walk(path):
        for f in fs:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def fetch(clone, ref, token=""):
    """Shallow-clone (cached). Returns dict(dir, commit, ref)."""
    key = (clone, ref)
    now = time.time()
    with _lock:
        for k in [k for k, v in _cache.items() if now - v["t"] > CACHE_TTL]:
            shutil.rmtree(_cache.pop(k)["root"], ignore_errors=True)
        if key in _cache and not token:
            _cache[key]["t"] = now
            return _cache[key]
    root = Path(tempfile.mkdtemp(prefix="git-"))
    dest = root / "repo"
    env = _env(token)
    try:
        dest.mkdir()
        _git(["init", "-q"], dest, env)
        _git(["remote", "add", "origin", clone], dest, env)
        target = ref or "HEAD"
        _git(["fetch", "-q", "--depth", "1", "--no-tags", "origin", target], dest, env)
        _git(["checkout", "-q", "FETCH_HEAD"], dest, env)
        if _du(dest) > GIT_MAX_MB * 1024 * 1024:
            raise GitError(f"repository is larger than {GIT_MAX_MB} MB. Point at a smaller repo or raise GIT_MAX_MB")
        commit = _git(["rev-parse", "--short", "HEAD"], dest, env)
        shutil.rmtree(dest / ".git", ignore_errors=True)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    entry = dict(root=str(root), dir=str(dest), commit=commit, ref=ref or "default branch", t=now)
    with _lock:
        if len(_cache) >= CACHE_MAX:
            oldest = min(_cache, key=lambda k: _cache[k]["t"])
            shutil.rmtree(_cache.pop(oldest)["root"], ignore_errors=True)
        if not token:  # never cache content fetched with a user's private token
            _cache[key] = entry
    return entry


def find_charts(repo_dir, max_depth=6):
    base = Path(repo_dir)
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        rel = Path(dirpath).relative_to(base)
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "vendor"))
        if len(rel.parts) >= max_depth:
            dirnames[:] = []
        if "Chart.yaml" in filenames:
            out.append(rel.as_posix() if rel.parts else ".")
            dirnames[:] = [d for d in dirnames if d != "charts" and d != "templates"]
    return out[:300]


def resolve_chart(repo_dir, path):
    base = Path(repo_dir).resolve()
    target = (base / path).resolve() if path else base
    if target != base and not str(target).startswith(str(base) + os.sep):
        raise GitError("path escapes the repository")
    if not target.is_dir():
        raise GitError(f"'{path}' isn't a folder in this repository")
    return target
