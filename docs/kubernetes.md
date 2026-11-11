# Running torrentd on Kubernetes

What a cluster must give torrentd, then how to deploy it with the Helm chart
through FluxCD. The chart is [`deploy/helm/torrentd`](../deploy/helm/torrentd),
published with every release as `oci://ghcr.io/d18580b/charts/torrentd`
([README, Install](../README.md#install)). [`running.md`](running.md) stays
the reference for every daemon setting; this page names the section that
explains each requirement rather than repeating it.

Each requirement is stated as **required** (the daemon, or the chart, refuses
or misbehaves without it) and then **recommended**.

## Requirements

### Cluster

- **Required:** Kubernetes 1.29 or later; on k3s, a `v1.29.x+k3s1` release or
  later. The chart's `kubeVersion` refuses anything older. Nodes are
  `linux/amd64` or `linux/arm64`: the image is a manifest list of those two,
  and no other architecture is built.
- **Recommended:** a Kubernetes minor the project still patches. FluxCD 2.6 or
  later, for the `source.toolkit.fluxcd.io/v1` `OCIRepository` used below.

### Kernel

Only `vpn` profiles and the kill switch need anything of the node's kernel; a
host-only deployment needs none of this.

- **Required, WireGuard:** the `wireguard` module loaded on the node
  (`modprobe wireguard`; in-tree since Linux 5.6). A container cannot load it.
  The boot checks for it and fails each WireGuard profile with
  `preflight wireguard_kernel:` where it is missing
  ([running.md §8, *In a container*](running.md#in-a-container)). The image is
  WireGuard-only: an OpenVPN profile cannot come up in it.
- **Required, kill switch:** nf_tables in the node's kernel. The image ships
  `nft`; a kill switch whose `nft list tables` does not run fails the boot.
- **Required, `rp_filter`:** `net.ipv4.conf.all.rp_filter = 2` in the pod's
  network namespace for any `vpn` profile. A profile whose tunnel comes up
  under strict reverse-path filtering is failed with
  `reason="rp_filter_strict"` ([running.md §7](running.md#7-limits-and-sysctls)).
  The sysctl is an unsafe one to Kubernetes, so the kubelet must allow it. On
  k3s, start the server or agent with
  `--kubelet-arg=allowed-unsafe-sysctls=net.ipv4.conf.*` (or the narrower
  `net.ipv4.conf.all.rp_filter`), then set `rpFilterLoose: true` in the
  chart's values. Without the kubelet flag the pod is refused with
  `SysctlForbidden`.
- **Recommended:** Linux 5.7 or later for `vpn` profiles. Before 5.7,
  binding a socket to the tunnel device needs `CAP_NET_RAW`, which the pod is
  not given, so less traffic is pinned to the tunnel before a fence trips
  ([running.md §11](running.md#11-drills-worth-doing-once-before-you-trust-it),
  drill 5).

### Pod Security Admission

The namespace's `pod-security.kubernetes.io/enforce` level must admit the pod
the chart renders from your values:

| The values ask for | Why | Lowest level that admits it |
| --- | --- | --- |
| Any `vpn` profile or `network_kill_switch` | `capabilities.add: [NET_ADMIN]`, outside `baseline`'s list, and `allowPrivilegeEscalation: true`, without which `no_new_privs` voids the image's `cap_net_admin+p` file capability ([running.md §8](running.md#in-a-container)) | `privileged` |
| `rpFilterLoose: true` | `net.ipv4.conf.all.rp_filter` is not in `baseline`'s safe sysctls | `privileged` |
| A `hostPath` payload volume, or `peers.expose: hostPort` | `baseline` forbids both | `privileged` |
| None of those: host-only, payload on claims, peers on a LoadBalancer or not exposed | The container drops every capability, runs as uid 1000 with `allowPrivilegeEscalation: false` and `seccompProfile: RuntimeDefault`, and mounts only claims, Secrets and an `emptyDir` | `restricted` |

A VPN deployment therefore runs in a namespace of its own labelled
`privileged`; keep nothing else there.

### Storage: the state volume

`/var/lib/torrentd`: the registry, the pool index, the resume and `.torrent`
stores, and the single-instance lock. The chart claims it from the
StatefulSet's `volumeClaimTemplates` (`persistence.*`).

- **Required:**
  - `ReadWriteOnce`, on a local POSIX filesystem (ext4, xfs, btrfs, zfs) or
    replicated block storage formatted with one (Longhorn, Ceph RBD).
  - Never NFS, CIFS/SMB or FUSE, and never the container's own layer: the boot
    refuses overlayfs, NFS, CIFS and FUSE under the state directory with exit
    `78` ([operations.md, *Storage the daemon runs on*](operations.md#storage-the-daemon-runs-on)).
    Both databases run SQLite in WAL mode, and the instance lock is a `flock`.
  - Honest `fsync` (a write acknowledged is on stable storage), working
    `flock`, and `renameat2`. Every resume save is temp, `fsync`, rename,
    `fsync` of the directory.
- **Recommended:**
  - SSD or NVMe. The `pool-adopt` bench (`crates/torrentd-bench/budgets.toml`)
    measured 15 to 28 ms per adopted torrent on a volume taking 10 to 30 ms
    per `fsync`, and that latency is most of it: about 3 to 5 minutes for 10k
    torrents there, far less on NVMe. `pool-scan` indexed 1M files in 14 s on
    btrfs over NVMe.
  - Size. The benches measure memory and time, not the volume, so these are
    estimates from what the directory holds
    ([operations.md, *What is in the state directory*](operations.md#what-is-in-the-state-directory)):
    a `.torrent` holds 20 bytes per piece plus its file list, its resume data
    a little more, and `pool.db` a row per indexed file. Budget 1 MiB per
    torrent across the stores and 1 KiB per indexed file:

    | Library | State volume |
    | --- | --- |
    | 1k torrents, 100k files | 2Gi |
    | 10k torrents, 1M files | 10Gi to 20Gi (the chart's default is 10Gi) |

    Measure it after the first scan (`kubectl exec torrentd-0 -- du -sh /var/lib/torrentd`)
    and grow the claim if your StorageClass allows expansion.

### Storage: payload volumes

`payloadVolumes` in the values: each an `existingClaim` or a `hostPath`,
holding `default_save_path` and any `[pool] roots`.

- **Required:**
  - Readable by uid 1000, and writable by it where it holds
    `default_save_path`: the daemon runs as uid and gid 1000.
  - Never a recursive `fsGroup` chown. The chart sets
    `fsGroupChangePolicy: OnRootMismatch` and never relabels a `hostPath`,
    but `OnRootMismatch` still walks the whole volume once when its root's
    group is not 1000. Make the root group-owned by gid 1000 before the first
    mount, and a large library is never walked.
  - No two pool roots that are one tree seen twice, such as two `hostPath`
    entries taken from nested host directories: the boot refuses roots that
    alias by bind mount or by nesting on one device (`crates/torrentd/src/config/mounts.rs`).
- **For `[pool] allow_mutations = true`, required:**
  - A local filesystem supporting `renameat2(RENAME_NOREPLACE)` and directory
    `fsync`. Each root is probed at boot; one that fails has its mutations
    disabled alone, with `torrentd_pool_root_mutations_disabled` raised
    ([operations.md](operations.md#storage-the-daemon-runs-on)).
  - One filesystem per root. A cross-device move of an unloaded torrent's
    directory is refused, and the trash is `<root>/.torrentd-trash`.
- **Read-only use** (`allow_mutations = false`, the default) works on any
  filesystem: a library on a read-only NFS claim is scanned, matched and
  seeded from.

### Network

- **Peer ports (required for incoming peers on a `host` profile):** list each
  in `peers.ports`, and expose them with `peers.expose`:
  - `hostPort`: the port on the node's own address. Simple on a single node;
    it needs a `privileged` namespace.
  - `loadBalancer`: a LoadBalancer Service (k3s's ServiceLB, MetalLB) with
    `externalTrafficPolicy: Local`, set by the chart, so a peer's address
    reaches the daemon unrewritten.

  A `vpn` profile's port lives on its tunnel and is never exposed here.
- **NetworkPolicy (required):** a CNI that enforces it. The chart's policy
  is what keeps every pod but the ingress controller and Prometheus off the
  API, because `trusted_proxies` trusts the whole pod CIDR
  ([running.md §6a](running.md#6a-reverse-proxy)). k3s enforces it with its
  embedded controller unless started with `--disable-network-policy`; plain
  flannel elsewhere does not. Set `networkPolicy.ingressControllerNamespaces`
  and `prometheusNamespaces` to where yours run.
- **Cluster addresses (required where they differ from k3s's):**
  `cluster.podCIDR` (default `10.42.0.0/16`) and `cluster.dnsIP` (default
  `10.43.0.10`, the `kube-dns` Service's ClusterIP).
- **The kill switch's DNS carve-out (privacy):** with `network_kill_switch`,
  the chart lets the daemon's DNS reach `cluster.dnsIP`, because the pod's
  `/etc/resolv.conf` names it and trackers would not resolve otherwise. Every
  tracker hostname the daemon looks up is then visible to CoreDNS and to
  whatever it forwards to. The boot warns, and
  `torrentd_kill_switch_dns_exempt` is `1`. Peer and tracker connections still
  leave only through the tunnels
  ([running.md §11, *In a cluster*](running.md#11-drills-worth-doing-once-before-you-trust-it)).
  Where that exposure is unacceptable, use per-profile in-tunnel resolvers
  ([running.md, *Tracker lookups through a tunnel*](running.md#tracker-lookups-through-a-tunnel)).

### Resources

From the `memory-scaling` and pool benches (`crates/torrentd-bench/budgets.toml`):
a seeding torrent costs 26 KiB resident over the empty session (budgeted at
52 KiB), and a first scan of 1M files peaks at 185 MiB (budgeted at
384 MiB). Neither bench reads payload, so libtorrent's disk buffers are on
top, and so is `/tmp`, a memory-backed `emptyDir` counted against the
container's memory.

| Library | Memory request | Memory limit | CPU request | CPU limit |
| --- | --- | --- | --- | --- |
| 1k torrents | 256Mi | 1Gi | 250m | none, or 4 |
| 10k torrents | 1Gi | 2Gi | 1 | none, or 4 |

Watch `container_memory_working_set_bytes` for the first week and move the
request to what it settles at.

**Keep the CPU limit generous during adoption.** Adopting a torrent that has
no complete fast-resume hashes its payload, and a first scan stats every
file: both run as fast as the CPU allows. A CPU limit well below that work
throttles every thread of the container alike, the async runtime's
twice-a-second tick included, and `/livez` answers 503 `runtime_stalled` once
that tick is 2 seconds old ([running.md §9](running.md#9-first-run-checks)), and three failed probes
restart the pod in the middle of the adoption. Leave the CPU limit off, or
well above the request, until the library is adopted.

Raise `probes.startup.failureThreshold` (default 180, 30 minutes) for a large
library: the API does not listen until the boot's scans finish.

## Setup

### Bootstrapping secrets

`hash-password` and `new-token` need a config file that parses, not one the
daemon would start from; the image carries the sample at
`/etc/torrentd/torrentd.toml.sample`. Run them in a throwaway pod of the
release's image (in a namespace that does not enforce `restricted`, since
`kubectl run` sets no `securityContext`):

```bash
v=X.Y.Z
kubectl run torrentd-bootstrap --rm -it --restart=Never \
  --image=ghcr.io/d18580b/torrent:$v --command -- \
  /usr/local/bin/torrentd --config /etc/torrentd/torrentd.toml.sample hash-password
kubectl run torrentd-bootstrap --rm -it --restart=Never \
  --image=ghcr.io/d18580b/torrent:$v --command -- \
  /usr/local/bin/torrentd --config /etc/torrentd/torrentd.toml.sample \
  new-token --name prometheus --scopes metrics
```

`new-token` prints the token (`tdp_…`) and then the config stanza holding its
SHA-256. Keep the token for the scrape's Secret, and the stanza's `sha256` for
the daemon's values ([running.md §6](running.md#6-authentication--required-one-way-or-the-other)).

Put the secrets in the Git repository Flux reads, encrypted with
[SOPS](https://fluxcd.io/flux/guides/mozilla-sops/):

```yaml
# torrentd-secrets.yaml, encrypted before it is committed:
#   sops --encrypt --encrypted-regex '^(data|stringData)$' --in-place torrentd-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: torrentd-values          # merged into the chart's values (valuesFrom)
  namespace: torrentd
stringData:
  values.yaml: |
    config:
      settings:
        auth:
          password_hash: "$argon2id$v=19$..."
          token:
            - name: prometheus
              sha256: "..."
              scopes: [metrics]
---
apiVersion: v1
kind: Secret
metadata:
  name: torrentd-metrics-token   # metrics.serviceMonitor.tokenSecret
  namespace: torrentd
stringData:
  token: tdp_...
---
# VPN only: one key per profile, named <vpn_interface>.conf (vpn.wireguardSecret).
apiVersion: v1
kind: Secret
metadata:
  name: torrentd-wireguard
  namespace: torrentd
stringData:
  wg-acct-a.conf: |
    [Interface]
    ...
  wg-acct-b.conf: |
    [Interface]
    ...
```

The Flux `Kustomization` that applies the directory decrypts them with
`spec.decryption: {provider: sops, secretRef: {name: sops-age}}`.

### Flux

An `OCIRepository` that refuses any chart the release workflow did not sign,
and a `HelmRelease` built from it:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: torrentd
  labels:
    # restricted for a host-only deployment on claims (see Pod Security Admission).
    pod-security.kubernetes.io/enforce: privileged
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: torrentd
  namespace: torrentd
spec:
  interval: 1h
  url: oci://ghcr.io/d18580b/charts/torrentd
  ref:
    semver: "0.2.x"
  layerSelector:
    mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip
    operation: copy
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: ^https://token\.actions\.githubusercontent\.com$
        subject: ^https://github\.com/d18580b/torrent/\.github/workflows/release-plz\.yml@refs/heads/master$
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: torrentd
  namespace: torrentd
spec:
  interval: 1h
  chartRef:
    kind: OCIRepository
    name: torrentd
  # Helm waits for the pod to be ready, and the startup probe allows 30 minutes.
  timeout: 35m
  valuesFrom:
    - kind: Secret
      name: torrentd-values
      valuesKey: values.yaml
  values:
    # One of the two below.
```

The chart's `version` and `appVersion` are the release's, so the chart a
`semver` range resolves runs the image of the same release. The identity is
the one [README, Install](../README.md#install) verifies with `cosign verify`.

#### Values: host-only

One public profile, its peer port on a LoadBalancer, the payload and a
read-only pool on claims, and the whole monitoring stack. It runs in a
`restricted` namespace.

```yaml
config:
  settings:
    log_level: info
    profile:
      - id: public
        network: host
        listen_interfaces: "0.0.0.0:6881"
        dht: true
    pool:
      roots: [/data/library]
      library_dir: /var/lib/torrentd/library
      allow_mutations: false
    telemetry:
      otlp_endpoint: http://alloy.monitoring.svc:4318
peers:
  ports:
    - name: public
      port: 6881
  expose: loadBalancer
payloadVolumes:
  - name: torrents
    mountPath: /data/torrents
    existingClaim: torrents
  - name: library
    mountPath: /data/library
    existingClaim: library
resources:
  requests: {cpu: "1", memory: 1Gi}
  limits: {memory: 2Gi}
ingress:
  enabled: true
  className: traefik
  hosts: [torrentd.example.com]
metrics:
  serviceMonitor:
    enabled: true
    tokenSecret:
      name: torrentd-metrics-token
  prometheusRule:
    enabled: true
  dashboard:
    enabled: true
```

#### Values: multi-account VPN behind the kill switch

Two WireGuard accounts and no `host` profile: with the kill switch on, the
daemon's uid reaches the network only through the tunnels, so the daemon
refuses at boot a config that sets `network_kill_switch = true` beside any
`host` profile. Run host profiles in a separate release without the kill
switch. The chart adds the kill switch's API and DNS
carve-outs, `NET_ADMIN`, and `allowPrivilegeEscalation: true` by itself. It
needs a `privileged` namespace, the kubelet's unsafe-sysctl flag, and the
`wireguard` module on the node.

```yaml
config:
  settings:
    network_kill_switch: true
    vpn_handshake_max_age_secs: 180
    shutdown_drain_secs: 300
    profile:
      - id: acct_a
        network: vpn
        vpn_type: wireguard
        vpn_config: /etc/wireguard/wg-acct-a.conf
        vpn_interface: wg-acct-a
        listen_port: 6891
        peer_fingerprint: "-qB5030-"
        user_agent: qBittorrent/5.0.3
        allowed_tracker_domains: [tracker-a.example.com]
      - id: acct_b
        network: vpn
        vpn_type: wireguard
        vpn_config: /etc/wireguard/wg-acct-b.conf
        vpn_interface: wg-acct-b
        port_forward: natpmp
        port_forward_gateway: 10.2.0.1
        peer_fingerprint: "-DE211s-"
        user_agent: Deluge/2.1.1 libtorrent/2.0.14.0
        allowed_tracker_domains: [tracker-b.example.com]
vpn:
  wireguardSecret: torrentd-wireguard
rpFilterLoose: true
payloadVolumes:
  - name: torrents
    mountPath: /data/torrents
    existingClaim: torrents
resources:
  requests: {cpu: 250m, memory: 256Mi}
  limits: {memory: 1Gi}
metrics:
  serviceMonitor:
    enabled: true
    tokenSecret:
      name: torrentd-metrics-token
  prometheusRule:
    enabled: true
  dashboard:
    enabled: true
```

Each profile's identity, port and tracker domains must stay distinct from
every other's ([running.md §5, *Account isolation*](running.md#account-isolation)).

### Observability wiring

- **`ServiceMonitor`** (`metrics.serviceMonitor`): scrapes `/metrics` with the
  `metrics`-scope token from `tokenSecret`, and sets `job="torrentd"`, which
  `TorrentdDown` matches. Needs the Prometheus Operator's CRDs, and a
  Prometheus whose `serviceMonitorSelector` matches `labels` and whose
  namespace is in `networkPolicy.prometheusNamespaces`.
- **`PrometheusRule`** (`metrics.prometheusRule`):
  [`deploy/prometheus/torrentd.rules.yml`](../deploy/prometheus/torrentd.rules.yml),
  the same rules a plain Prometheus loads.
- **Grafana dashboard** (`metrics.dashboard`): a ConfigMap labelled
  `grafana_dashboard: "1"` holding [`deploy/dashboard.json`](../deploy/dashboard.json),
  for the Grafana chart's dashboard sidecar. Point the sidecar at the
  release's namespace, or at all of them.
- **OTLP traces:** `config.settings.telemetry.otlp_endpoint`, as in the
  host-only values: Grafana Alloy's OTLP receiver (`:4318`, http/protobuf), or
  Tempo's own (`:4317` with `protocol: grpc`)
  ([running.md §9, *Traces*](running.md#traces-opentelemetry-over-otlp)).
  With the kill switch on, the daemon's only egress is loopback and its
  tunnels, so the collector must run in the same pod; the chart has no value
  for a sidecar, so leave `[telemetry]` off there. Trace and span ids are in
  every log line either way.

### Operations

**Reaching the API with `torrentctl`.** The static `torrentctl` from the
release runs on your own machine:

```bash
kubectl -n torrentd port-forward svc/torrentd 8080:8080
TORRENTCTL_TOKEN=tdp_... torrentctl --url http://127.0.0.1:8080
```

A port-forward reaches the API over the pod's loopback, so it works with the
kill switch on and is not subject to the NetworkPolicy. Through the Ingress
instead, `torrentctl --url https://torrentd.example.com`. Without a token it
asks for the operator password ([README, Operator client](../README.md#operator-client)).

**Backing up the state volume.** The image has no `sqlite3`, so the online
backup of [operations.md, *Backing up*](operations.md#backing-up) is not to
hand in the pod. Either:

- take a CSI `VolumeSnapshot` of `state-torrentd-0`. It holds what a power cut
  at that instant would leave: both databases are consistent on storage with
  honest `fsync`, and resume data is as of each torrent's last save; or
- stop the daemon and copy the whole volume, a consistent set
  ([operations.md, *Backing up*](operations.md#backing-up), *Offline*):
  `flux suspend helmrelease torrentd -n torrentd`, so no reconcile scales it
  back up, then `kubectl -n torrentd scale statefulset torrentd --replicas=0`,
  copy the volume from a pod that mounts the claim, scale back to 1, and
  `flux resume helmrelease torrentd -n torrentd`.

Neither backs up payload.

**The staged dogfood rollout.** Before it holds anything you care about:

1. **A read-only pool over a copy of the library.** `[pool] roots` on a copy,
   or on the library through a read-only claim, with
   `allow_mutations: false` and `library_dir` at a copy of the previous
   client's state ([import.md](import.md)). Scan, and read `pool status`.
2. **Adopt a few torrents.** A handful, from `torrentctl`'s pool view or the
   API, with a dry-run preview first. Watch them seed and the verify queue
   drain.
3. **The [running.md §11](running.md#11-drills-worth-doing-once-before-you-trust-it)
   drills.** Use pod deletion for the restarts and crashes: `kubectl delete pod
   torrentd-0` for drill 1's restart (a graceful stop within
   `terminationGracePeriodSeconds`), and
   `kubectl delete pod torrentd-0 --grace-period=0 --force` for drill 2's
   `kill -9`.
4. **One `vpn` profile.** Then `kubectl exec torrentd-0 -- torrentd --config
   /etc/torrentd/torrentd.toml vpn check`, and the kill switch's drills.
5. **`allow_mutations`.** Only on roots whose filesystem passed the boot's
   probe, starting with one root.
