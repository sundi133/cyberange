# Cloud attack surface

CyberRange ships six cloud-stage modules and a flagship cloud intrusion
scenario — the identity-plane techniques that account for the majority of
enterprise cloud incidents today. Honest framing of what ships, in what
posture, is below.

## What ships

| Module | ATT&CK | Pattern it exercises |
|---|---|---|
| `CR-MOD-CLOUD-METADATA-001` | T1552.005 | Instance-metadata credential-request pattern (`169.254.169.254` role-credentials path). |
| `CR-MOD-CLOUD-OAUTH-001` | T1528 | OAuth app consent-grant pattern (wide-scope delegated permissions). |
| `CR-MOD-CLOUD-ACCT-MANIP-001` | T1098 | Cloud account manipulation (trust-policy change + new access-key creation). |
| `CR-MOD-CLOUD-STORAGE-001` | T1530 | Cross-bucket bulk list / get-object pattern. |
| `CR-MOD-CLOUD-EXFIL-001` | T1567.002 | Egress to an external cloud-storage bucket. |
| `CR-MOD-CLOUD-MAILRULE-001` | T1114.003 | Mail-forwarding rule to an external address. |

Scenario `CR-CLOUD-FLAG-001` chains them under red-blue mode with timed
injects at each stage.

## Posture (Phase 1)

Each cloud module runs on the **Docker tier** — a short, egress-denied
`alpine` container that emits labelled telemetry markers via `echo`. The
detection engine fires log-basis rules on the markers; off Docker, the
simulated adapter fires technique-basis coverage rules. **No cloud account
is touched.** The value is end-to-end detection training on the shape of a
cloud-era intrusion.

This is the same pattern the Linux-real modules use. It is not a trick: a
cyber range is a detection-training lab, and the training signal is the
telemetry a defender hunts.

## Posture (Phase 2, customer plug-in)

The `CloudProvisioner` protocol lives at
`backend/cyberrange/provisioners/cloud.py`. The shipped
`MarkerCloudProvisioner` satisfies the protocol by executing marker commands
on the local Docker tier. A customer bringing a cloud sandbox account
subclasses it and overrides `exec_in` to call the SDK of their choice:

```python
import boto3
from cyberrange.provisioners.cloud import MarkerCloudProvisioner
from cyberrange.provisioners.base import ExecResult


class BotoCloudProvisioner(MarkerCloudProvisioner):
    def __init__(self, *, sandbox, aws_profile):
        super().__init__("aws", sandbox=sandbox)
        self._sess = boto3.Session(profile_name=aws_profile)

    def exec_in(self, range_id, target, cmd, timeout=60):
        # Interpret `cmd` as the SDK call to make. One example:
        if cmd[:3] == ["cloud", "s3", "list"]:
            s3 = self._sess.client("s3")
            resp = s3.list_objects_v2(Bucket=cmd[3])
            return ExecResult(
                stdout="\n".join(obj["Key"] for obj in resp.get("Contents", [])),
                stderr="", returncode=0, duration_s=0.1)
        return super().exec_in(range_id, target, cmd, timeout)
```

The control plane uses the standard library only; a customer plugs in `boto3`
/ `azure-sdk` / `google-cloud-*` on the module path they manage. The
provisioner contract is small on purpose: four methods and nothing else.

## Running the cloud tier

Set the env before starting the server. The resolver prefers the VM tier
when both are set, so if a cloud-focused deployment also has Proxmox
configured, un-set `CR_PROXMOX_HOST` or let the VM tier run the Windows
scenarios while the Docker tier runs the cloud ones:

```
export CR_CLOUD_PROVIDER=aws        # one of: aws, azure, gcp
export CR_CLOUD_SANDBOX=cr-sandbox-prod-cx1   # optional; a random id otherwise
```

`/api/health` reports the tier that was picked and why (e.g.
`"cloud tier (aws)"`). If the env is set but a required credential is
missing, the resolver falls back to the container tier and names the
rejection reason instead of silently downgrading.

## Credentials and licensing

Phase 1 needs **no cloud credentials** — the modules emit telemetry markers,
not API calls. Phase 2 (your `BotoCloudProvisioner` or equivalent) needs:

- A **scoped cloud sandbox account** you own, isolated from production.
- Read-only credentials where possible; write scopes only for the stages
  you actually want to execute (`CR-MOD-CLOUD-ACCT-MANIP-001`,
  `CR-MOD-CLOUD-MAILRULE-001` write, so they require policy approval).
- An audit sink (CloudTrail / Azure Audit / GCP Admin Activity) you point
  the blue team at — the cloud chain's whole teaching value is that the
  signal lives there, not on endpoints.

No cloud license is required beyond the sandbox account itself. The
platform remains stdlib-only; SDK dependencies live in the customer's
own Phase-2 adapter.

## What's deliberately out of scope here

- Real cloud credentials in this repository. The adapter is a seam; the
  SDK choice is the customer's.
- SigV4 / Azure AD token exchange / GCP IAM handling in platform code. A
  customer's chosen SDK handles these; the platform should not re-implement
  them.
- Destructive cloud actions. Even in a customer-owned sandbox, modules
  stay bounded (lab-only buckets, lab-only app registrations). Nothing in
  the shipped content performs an irreversible operation on a real account.
