"""Live container ranges.

When CR_LIVE_RANGES=1 and Docker is available, provisioning a range stands up a
real, persistent per-range environment instead of pure control-plane state:

  - an isolated bridge network (``--internal`` => no egress, default-deny),
  - a persistent "victim" host container the learner operates on (a foothold
    that persists across lesson steps), and
  - a networked "webapp" target reachable from the victim over the range network
    (so behaviors can traverse a real, connected target set).

TTP modules then run *inside* the victim (docker exec) rather than in throwaway
containers, so state carries across steps and targets are reachable by hostname.
`reset` recycles the targets; `teardown` removes them with the network.

Everything is labelled ``cyberrange=<range_id>`` for reliable cleanup. Non-
privileged, memory/pid capped, no host mounts, no internet.
"""

from __future__ import annotations

import subprocess

BASE_IMAGE = "alpine:3.19"

# Directory / identity target (a real Linux OpenLDAP domain - an AD-style
# identity attack surface; NOT a Windows AD DC, which needs the VM tier).
DIR_IMAGE = "osixia/openldap:1.5.0"
DIR_BASE = "dc=range,dc=lab"
DIR_ADMIN_DN = "cn=admin,dc=range,dc=lab"
DIR_ADMIN_PW = "adminpw"
# Seeded synthetic users; alice + svc-backup deliberately reuse a password.
_SEED_LDIF = """dn: ou=people,dc=range,dc=lab
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=range,dc=lab
objectClass: inetOrgPerson
cn: Alice Admin
sn: Admin
uid: alice
userPassword: Autumn2024!

dn: uid=svc-backup,ou=people,dc=range,dc=lab
objectClass: inetOrgPerson
cn: Backup Service
sn: Service
uid: svc-backup
userPassword: Autumn2024!

dn: uid=bob,ou=people,dc=range,dc=lab
objectClass: inetOrgPerson
cn: Bob Analyst
sn: Analyst
uid: bob
"""


def _short(range_id: str) -> str:
    return range_id.replace("range-", "")[:16]


def net_name(range_id: str) -> str:
    return f"cr-{_short(range_id)}"


def victim_name(range_id: str) -> str:
    return f"cr-{_short(range_id)}-victim"


def web_name(range_id: str) -> str:
    return f"cr-{_short(range_id)}-webapp"


def dc_name(range_id: str) -> str:
    return f"cr-{_short(range_id)}-dc"


def _run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _exists(kind: str, name: str) -> bool:
    # kind: "container" or "network"
    if kind == "container":
        r = _run(["docker", "ps", "-aq", "-f", f"name=^{name}$"])
    else:
        r = _run(["docker", "network", "ls", "-q", "-f", f"name=^{name}$"])
    return r.returncode == 0 and bool(r.stdout.strip())


def _running(name: str) -> bool:
    r = _run(["docker", "ps", "-q", "-f", f"name=^{name}$"])
    return r.returncode == 0 and bool(r.stdout.strip())


def is_provisioned(range_id: str) -> bool:
    return _running(victim_name(range_id))


def provision(range_id: str, with_directory: bool = False) -> dict:
    """Create the range network + persistent targets (idempotent)."""
    net, victim, web = net_name(range_id), victim_name(range_id), web_name(range_id)
    label = f"cyberrange={range_id}"

    if not _exists("network", net):
        _run(["docker", "network", "create", "--internal", "--label", label, net])

    if not _exists("container", victim):
        _run(["docker", "run", "-d", "--name", victim, "--hostname", "victim",
              "--network", net, "--label", label, "--memory=256m",
              "--pids-limit=256", "--security-opt=no-new-privileges",
              BASE_IMAGE, "sleep", "infinity"])
    elif not _running(victim):
        _run(["docker", "start", victim])

    if not _exists("container", web):
        # A tiny reachable web target named `webapp`. Alpine's busybox has no
        # httpd applet, so serve a fixed 200 with a busybox `nc` loop.
        _run(["docker", "run", "-d", "--name", web, "--hostname", "webapp",
              "--network", net, "--label", label, "--memory=128m",
              "--pids-limit=128", "--security-opt=no-new-privileges", BASE_IMAGE,
              "sh", "-c",
              'while true; do printf "HTTP/1.1 200 OK\\r\\nConnection: close\\r\\n'
              '\\r\\n<h1>vulnerable-app</h1>" | nc -l -p 80; done'])
    elif not _running(web):
        _run(["docker", "start", web])

    targets = [
        {"name": victim, "hostname": "victim", "role": "foothold host"},
        {"name": web, "hostname": "webapp", "role": "web target"},
    ]
    if with_directory:
        provision_directory(range_id)
        targets.append({"name": dc_name(range_id), "hostname": "dc",
                        "role": "directory (LDAP identity)"})
    return {"network": net, "targets": targets}


def provision_directory(range_id: str) -> bool:
    """Stand up a real OpenLDAP directory seeded with synthetic domain users.
    Returns True once accounts are queryable."""
    net, dc = net_name(range_id), dc_name(range_id)
    label = f"cyberrange={range_id}"
    if not _exists("container", dc):
        _run(["docker", "run", "-d", "--name", dc, "--hostname", "dc",
              "--network", net, "--label", label, "--memory=512m",
              "-e", "LDAP_ORGANISATION=Range Lab", "-e", "LDAP_DOMAIN=range.lab",
              "-e", f"LDAP_ADMIN_PASSWORD={DIR_ADMIN_PW}", DIR_IMAGE])
    elif not _running(dc):
        _run(["docker", "start", dc])
    # Wait for slapd, then seed users (idempotent - ignores "already exists").
    import time
    for _ in range(30):
        chk = _run(["docker", "exec", dc, "ldapsearch", "-x", "-H", "ldap://localhost",
                    "-b", DIR_BASE, "-D", DIR_ADMIN_DN, "-w", DIR_ADMIN_PW, "-s", "base"])
        if chk.returncode == 0:
            break
        time.sleep(2)
    else:
        return False
    subprocess.run(["docker", "exec", "-i", dc, "ldapadd", "-x", "-H", "ldap://localhost",
                    "-D", DIR_ADMIN_DN, "-w", DIR_ADMIN_PW],
                   input=_SEED_LDIF, text=True, capture_output=True, timeout=30)
    return True


def directory_provisioned(range_id: str) -> bool:
    return _running(dc_name(range_id))


def exec_in_directory(range_id: str, cmd: list[str], timeout: int = 60):
    """Run a command inside the directory (LDAP) container."""
    import time
    dc = dc_name(range_id)
    t0 = time.monotonic()
    proc = _run(["docker", "exec", dc, *cmd], timeout=max(5, min(timeout, 120)))
    return proc.stdout, proc.stderr, proc.returncode, round(time.monotonic() - t0, 3)


def exec_in_victim(range_id: str, cmd: list[str], timeout: int = 60):
    """Run a command inside the persistent victim host. Returns
    (stdout, stderr, returncode, duration_s)."""
    import time
    victim = victim_name(range_id)
    t0 = time.monotonic()
    proc = _run(["docker", "exec", victim, *cmd], timeout=max(5, min(timeout, 120)))
    return proc.stdout, proc.stderr, proc.returncode, round(time.monotonic() - t0, 3)


def reset(range_id: str) -> dict:
    """Recycle the target containers (fresh state), keeping the network."""
    had_dir = directory_provisioned(range_id)
    for name in (victim_name(range_id), web_name(range_id), dc_name(range_id)):
        _run(["docker", "rm", "-f", name])
    return provision(range_id, with_directory=had_dir)


def teardown(range_id: str) -> None:
    """Remove all containers + the network for this range (best effort)."""
    r = _run(["docker", "ps", "-aq", "-f", f"label=cyberrange={range_id}"])
    ids = [i for i in r.stdout.split() if i]
    if ids:
        _run(["docker", "rm", "-f", *ids])
    if _exists("network", net_name(range_id)):
        _run(["docker", "network", "rm", net_name(range_id)])
