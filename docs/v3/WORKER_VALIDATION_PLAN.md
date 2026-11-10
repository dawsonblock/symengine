# Linux Worker Validation Plan

## Purpose

Move `sis.v3.linux_worker` from "scaffold probed in a privileged
container" to a production-qualified containment boundary. A passing
probe is platform evidence for the isolator; it is not a qualification
claim, and this plan does not prove the absence of kernel or hypervisor
escapes.

## Current evidence (2026-11-09)

- `tools/linux_worker_probe.py`: 13/13 on Debian 12, bubblewrap 0.8.0,
  Python 3.11.2, LinuxKit 7.0.14, with a host-mounted cgroup v2
  hierarchy. The container was **privileged** because that kernel denied
  unprivileged user namespaces.
- Inner seccomp denylist applied after bwrap setup: `Seccomp: 2`;
  `unshare` and `mount` return `EPERM`.
- cgroup v2 `pids.max` / `memory.max`; hardened read-only `/etc`;
  network namespace; process-group kill; environment scrubbing.
- Not yet validated: unprivileged user namespaces on a real host, a
  production host or microVM, microVM image/kernel binding, independent
  isolator custody.

## Option A — dedicated rootless host (fastest path)

Host prerequisites:

- Linux with unprivileged user namespaces enabled (distribution default
  or `kernel.unprivileged_userns_clone=1`), cgroup v2 delegated to the
  worker account, seccomp available.
- A dedicated worker account with no evaluator keys, no registry access,
  and no useful home directory contents.
- `bubblewrap` installed; user-namespace mode preferred over setuid.
- No Docker or other privileged container in the execution path.

Validation steps:

1. Run `tools/linux_worker_probe.py` as the worker account; require
   13/13.
2. Confirm `Seccomp: 2`, `unshare`/`mount` `EPERM`, and that the
   `seccomp:inner_filter`, `net:denied`, `fs:workspace_confined`,
   `proc:namespaced`, `cgroup:v2` markers are present.
3. Confirm cgroup pids and memory bounds with `cgroup_pids` and
   `cgroup_memory` (a quick `EAGAIN`/OOM is preferred; a wall-clock stop
   still proves the bound but should be investigated).
4. Confirm no host path is visible: read and write probes must fail.
5. Confirm the process-group probe leaves no surviving child.
6. Run `OutcomeVerifier` with a `ProductionIsolationPolicy` requiring
   those properties and issue a V2 receipt.

Acceptance: probe 13/13 on the target host, policy-attested V2 receipt,
no privileged container, no evaluator key material on the worker.

Residual risks: the host kernel is shared; a kernel bug can escape
bubblewrap. The host must be patched and dedicated to evaluation.

## Option B — microVM (strongest separation)

Use Firecracker or Cloud Hypervisor with a minimal Linux guest:

- One microVM per evaluation, or a pool with a verified reset.
- Read-only rootfs containing the worker and interpreter; an ephemeral
  writable disk for the workspace.
- No network device (vsock only for the control plane), or a filtered
  tap with an explicit policy.
- Guest kernel, initrd, rootfs and worker config digests pinned in the
  isolation policy.
- The worker runs inside the guest and emits the execution receipt; the
  isolator, outside the guest, signs the attestation over the receipt
  plus the image/kernel/config digests.
- No evaluator keys inside the guest; acceptance material is injected
  per evaluation.

Validation steps:

1. Boot the microVM, run the probe inside; require 13/13.
2. Confirm there are no host block devices, no shared folders
   (9p/virtiofs), and no network interface other than the control
   channel.
3. Confirm the guest image/kernel/config digests match the policy.
4. Red-team the guest boundary: `/dev`, `/proc/sys`, vsock, block
   devices, initrd, and any virtio device.
5. Confirm the attestation binds the exact receipt and image/kernel
   digests.

Acceptance: probe 13/13 inside the guest, digest-bound attestation,
independent isolator, no privileged host container.

Residual risks: hypervisor and guest-kernel vulnerabilities; vsock
control-plane authentication; image supply chain.

## Required controls (both options)

- No evaluator signing keys or registry access on the worker.
- Only the acceptance material supplied for that evaluation.
- Restricted network (namespace or no NIC).
- Read-only rootfs; one writable workspace; no host bind mounts.
- CPU, memory, wall-clock, disk, output and pids limits; process-group
  and cgroup kill.
- Seccomp denylist and no new privileges.
- Independent evidence: receipt plus attestation; no self-certification.

## Red-team checklist

- Filesystem: `/etc` writes, host paths, symlinks, `/proc/sys`, `/dev`,
  `mount`, `pivot_root`.
- Network: connect, DNS, raw sockets, vsock.
- Process: fork bomb, child escaping the process group, `ptrace`,
  `process_vm_readv`.
- Kernel: `bpf`, `perf_event_open`, `keyctl`, `userfaultfd`, modules.
- Resources: memory, disk, output, CPU, wall clock.
- Attestation: reuse for another receipt, wrong worker, expired,
  missing property.

## Production acceptance

1. Probe 13/13 on the target non-privileged host or microVM.
2. `ProductionIsolationPolicy` requires the verified properties,
   including `seccomp:inner_filter`.
3. Isolator key and witness custody are separate from the worker.
4. The release qualification report records the image/kernel/config
   digests, probe JSON and red-team results.
5. No privileged container in the execution path.

## Out of scope

- Proving the absence of kernel/hypervisor escapes.
- Proving the isolator is honest.
- Replacing an independent security review.
