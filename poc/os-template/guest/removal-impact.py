#!/usr/bin/python3
"""For every installed package, what removing it would take along (nothing is changed).

Written once per template build, after the upgrade. The SSI screen shows it as the list a
template profile is chosen from, with a live preview of each choice (src/lib/templateProfile.js).

Each package is simulated the way `apt-get --autoremove purge <package>` does it: the package,
every package that depends on it, then every automatically installed package nothing needs any
more. The apt cache is reset before every package, so one simulation can never leak into the
next; the work is spread over the CPUs. A package apt refuses to remove (essential, or one whose
removal cannot be resolved) is reported as refused.

Output, one JSON object per line, sorted by package:
  SCAN_DIR/out/removal-impact.jsonl
  {"package": "nano", "version": "7.2-2ubuntu0.2", "essential": false, "required": false,
   "refused": false, "cascade": ["nano"]}

Runs as root inside the build VM with the distribution's python3 and python3-apt.
"""
import json
import multiprocessing
import os
import sys

import apt
import apt_pkg

_cache = None


def _init_worker():
    global _cache
    _cache = apt.Cache()


def _installed_low(cache):
    return [package._pkg for package in cache if package.is_installed]


def simulate(name):
    """(name, version, essential, required, refused, cascade) for one package."""
    cache = _cache
    cache.clear()
    package = cache[name]
    installed = package.installed
    record = (name, installed.version, bool(package.essential), installed.priority == "required")
    try:
        with cache.actiongroup():
            package.mark_delete(auto_fix=True, purge=True)
    except apt_pkg.Error:
        return (*record, True, [name])
    depcache = cache._depcache
    low = _installed_low(cache)
    # What `--autoremove` adds: packages that became unused, until nothing more changes.
    while True:
        unused = [item for item in low if depcache.is_garbage(item) and not depcache.marked_delete(item)]
        if not unused:
            break
        with apt_pkg.ActionGroup(depcache):
            for item in unused:
                depcache.mark_delete(item, True)
    cascade = sorted(item.name for item in low if depcache.marked_delete(item))
    return (*record, False, cascade)


def main():
    out_dir = os.path.join(os.environ.get("SCAN_DIR", "/var/tmp/ssi-scan"), "out")
    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, "removal-impact.jsonl")
    names = sorted(package.name for package in apt.Cache() if package.is_installed)
    workers = max(1, int(os.environ.get("IMPACT_WORKERS", os.cpu_count() or 1)))
    with multiprocessing.Pool(workers, initializer=_init_worker) as pool:
        results = pool.map(simulate, names, chunksize=8)
    with open(target + ".tmp", "w", encoding="utf-8") as handle:
        for name, version, essential, required, refused, cascade in results:
            handle.write(json.dumps({
                "package": name,
                "version": version,
                "essential": essential,
                "required": required,
                "refused": refused,
                "cascade": cascade,
            }, separators=(",", ":")) + "\n")
    os.replace(target + ".tmp", target)
    os.chmod(target, 0o644)
    refused = sum(1 for item in results if item[4])
    print(f"Removal impact of {len(results)} installed packages ({refused} refused by apt) written to {target}.")


if __name__ == "__main__":
    sys.exit(main())
