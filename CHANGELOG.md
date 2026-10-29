# Changelog

Every release of torrentd and torrentctl, newest first. Both binaries share
one version and one `vX.Y.Z` tag; README.md § *Install* says how to download
a release and verify what you downloaded.

## [0.2.1](https://github.com/d18580b/torrent/compare/v0.2.0...v0.2.1) - 2026-10-29

### Fixed

- **torrentctl:** Stop the input thread before the terminal is handed back ([#697](https://github.com/d18580b/torrent/pull/697))

### Refactored

- **torrentctl:** Split the oversized screens and give screens a contract module ([#698](https://github.com/d18580b/torrent/pull/698))

### Documentation

- **torrentctl:** Make the doc comments match the code after the screens split ([#700](https://github.com/d18580b/torrent/pull/700))

### Tests

- **torrentd:** Check the netns leak counter after shutdown and across a crash ([#626](https://github.com/d18580b/torrent/pull/626))

## [0.2.0](https://github.com/d18580b/torrent/releases/tag/v0.2.0) - 2026-10-26

### Added

- **cli:** Torrentd vpn check — verify a VPN without seeding anything
- [**breaking**] Make every profile declare how it reaches the network
- [**breaking**] Refuse to run unauthenticated without saying so
- **http:** Support a reverse proxy, and serve assets like an origin server
- **http:** Read the client address from RFC 7239 Forwarded too
- **startup:** Warn at boot when the daemon authenticates nothing
- **metrics:** Seed slot_vpn_tunnel_up for a boot-failed slot
- **metrics:** Seed the probe gauge for a boot-failed wireguard slot
- **startup:** Log the parsed trusted-proxy set at boot
- **http:** Runtime control routes — recheck, reannounce, daemon-wide pause/resume, profile filters ([#45](https://github.com/d18580b/torrent/pull/45))
- **logging:** Redact tracker credentials from the daemon's JSON log ([#54](https://github.com/d18580b/torrent/pull/54))
- **port-forward:** Reannounce on a ProtonVPN port change and renew leases before they lapse ([#56](https://github.com/d18580b/torrent/pull/56))
- Turn every runtime error and warning into a seeded, alerted series ([#57](https://github.com/d18580b/torrent/pull/57))
- **deploy:** Grafana dashboard and the remaining #20 alert rules ([#62](https://github.com/d18580b/torrent/pull/62))
- **metrics:** Label NAT-PMP failures by stage and alert on each stage ([#64](https://github.com/d18580b/torrent/pull/64))
- Drill the engine-only alerts through a fault-injection build ([#63](https://github.com/d18580b/torrent/pull/63))
- **http:** [**breaking**] /v1 API on kynos with a generated OpenAPI 3.2 contract ([#69](https://github.com/d18580b/torrent/pull/69))
- [**breaking**] Keep the assignment registry in SQLite ([#83](https://github.com/d18580b/torrent/pull/83))
- **profiles:** Per-profile online/offline state with an instance-wide alias ([#124](https://github.com/d18580b/torrent/pull/124))
- **metrics:** Count directory fsync failures ([#147](https://github.com/d18580b/torrent/pull/147))
- **metrics:** Export the shim's alert translation failures as alert_translate_errors_total ([#300](https://github.com/d18580b/torrent/pull/300))
- **http:** An optional unix-socket API listener ([#341](https://github.com/d18580b/torrent/pull/341))
- **pool:** Report what a drift check could not see in the API, CLI and TUI ([#555](https://github.com/d18580b/torrent/pull/555))
- **pool:** List each library torrent's adoption note ([#641](https://github.com/d18580b/torrent/pull/641))

### Fixed

- **pool:** Derive the delete precondition from live state, not a counter
- **pool:** Unbrick interrupted plans, and make a panicked daemon exit non-zero
- **startup:** Do not clear the paused flag when loading resume data
- **engine:** Enforce the no-download invariant on every add path
- **pool:** Claim the registry before a session sees an adopted torrent
- **config:** Withhold enable_lsd from private slots on SIGHUP
- **vpn:** Make tunnel teardown and restart actually work
- **startup:** Never leave tunnels or a kill switch behind a failed boot
- **vpn:** Refuse a root kill switch, and report the safety state honestly
- **vpn:** Stop the handshake probe failing silently, and fix a lying metric
- **config:** Apply the settings that were parsed and then ignored
- **auth:** Throttle a client the tracked-client map has no room for
- **auth:** Let the tracked-client sweep actually reclaim an entry
- **http:** Read a forwarding header that arrived on several field lines
- **startup:** Refuse a registry that names an unconfigured profile
- **web:** Send profile_id when adopting from the pool view
- **signals:** Keep the listener serving after the first shutdown
- **http:** Treat Accept-Encoding q=0 as the refusal it is
- **startup:** Close the two boot paths that stranded a signal and a tunnel
- **config:** Settle what a slot's upload_rate_limit means, and report a change
- **engine:** Refuse a wireguard profile outside /etc/wireguard
- **vpn_monitor:** Seed the handshake probe gauge at its baseline
- **http:** Report one slot count from /healthz, and assert the body
- **openvpn:** Wait for the process to exit before dropping its pid file
- **config:** Report an auth or bind change on SIGHUP instead of "unchanged"
- **cli:** Let operator subcommands load a config the daemon would refuse
- **auth:** Pin the Argon2id cost that the README documents
- **config:** Refuse allow_unauthenticated alongside a configured [auth]
- **engine:** Apply Safety Rule 8 to host profiles, and key listen fatality on live sessions
- **config:** Treat an IPv4-mapped loopback bind as loopback
- **http:** Re-break the 409 login body and record what the status code is for
- **vpn-check:** Never lower a tunnel this command did not raise
- **vpn-check:** Stop the default path deleting the daemon's forward
- **vpn-check:** Let the exit status say when nothing was established
- **vpn-check:** Report what each host check actually establishes
- **http:** Count the slots /healthz says it counts
- **vpn:** Stop tearing down an interface we just refused to adopt
- **startup:** Subscribe the shutdown receivers before the listener exists
- **signals:** Stop honouring SIGHUP once a shutdown has been reported
- **vpn-check:** Negotiate NAT-PMP with a client that deletes nothing
- **vpn-check:** Take the bring-up and rp_filter verdicts from the host
- **vpn-check:** Let --as-uid produce a verdict, and keep unknown exceptional
- **vpn:** Exempt any interface this boot cannot establish is its own
- **docs:** Restore util-linux as the package that provides kill
- **vpn:** Let a later boot establish ownership without the profile's key
- **vpn-check:** Skip a profile with no tunnel rather than panicking
- **config:** Decide identity and store-directory uniqueness on effective values
- **http:** Stand the peer up when a trusted proxy's X-Forwarded-For will not parse
- **http:** Let X-Forwarded-Proto decide the scheme wherever it is present
- **config:** Report a trusted_proxies-only edit instead of calling it unchanged
- **config:** Load both samples in a test, and stop a reload clobbering a profile
- **registry:** Read the assignment file an upgrade actually has, and write the new one
- **startup:** Name the file the registry entries came from, and check what loaded
- **http:** Report a profile that failed to come up rather than denying it exists
- **auth:** Give a client whose failures went to the shared bucket a slot on success
- **profile:** Close the keys a false and a missing validator let through
- **cli:** Reproduce the kill-switch boot refusal in --check-config
- **http:** Report a delete whose assignment write failed
- **pool:** Say which of the two torrent-to-profile mappings wins
- **http:** Make a stale assignment's clear survive the next restart
- **vpn-check:** Classify nft --check on what nft reported, not on who asked
- **vpn-check:** Settle a refused handshake against the link type, not privilege
- **vpn-check:** Stop an unsettleable uid mismatch colouring the exit status
- **vpn-check:** Keep an excluded slot's interface out of a scoped run's status
- **vpn-check:** Two report texts that named a mechanism that was not in play
- **vpn:** Bound what a raised-interface record may claim
- **metrics:** Keep one meaning for slot_vpn_handshake_probe_ok
- **reload:** Report every key a SIGHUP cannot apply
- **cli:** Refuse --check-config given beside a subcommand
- **vpn-check:** Hold --bring-up to the daemon's posture check
- **registry:** Name the file, the id and the remedy for an unusable legacy id
- **config:** Refuse only an equal store directory, not a contained one
- **http:** Answer for a configured profile that never got a session
- **http:** Order a delete so its own failure message is true
- **config:** Accept two host profiles that both inherit one identity
- **http:** Require application/json on POST /api/login
- **config:** Refuse a trusted_proxies entry that trusts every peer
- **http:** Decide a forwarding header's arm on presence, not on readability
- **config:** Make a per-profile upload_rate_limit of 0 mean unlimited
- **http:** Read Accept-Encoding across field lines, and honour a later q=0
- **auth:** Never evict a locked-out entry to make room for a success
- **http:** Give a precompressed representation its own ETag
- **http:** Clear the session cookie with the same Secure attribute it was set with
- **reload:** Report a reloadable key withheld from a profile
- **config:** Check the authentication posture after every shape check
- **main:** Stop promising an exemption the invocation does not have
- **deploy:** State the identity and directory rules the validator enforces
- **http:** Resolve a profile id through one method, not five hand-rolled pairs
- **reload:** Stop calling a rate-limit edit an identity change
- **config:** Refuse a universal trusted_proxies prefix on the parsed value
- **startup:** Name both registry files in the reconciliation warning
- **http:** Take the last forwarding element positionally, readable or not
- **auth:** Clear a held throttle entry by replacing it, not by removing it
- **auth:** Stop a consult that never becomes an attempt refreshing liveness
- **http:** Split Forwarded outside quoted strings and unquote per RFC 7239
- **http:** Take the scheme from the outermost hop, not the nearest one
- **http:** Close five edges of the static server
- **http:** Resolve one hop, and spell a v4-mapped client one way
- **deploy:** Install procps-ng for wg-quick's sysctl call
- **vpn:** Key the raised-interface record to the link, not its name
- **vpn:** Keep the raised-interface record when teardown leaves the link up
- **http:** Make the registry's live lookup private to the registry
- **vpn:** Report a state directory the sweep cannot read
- **startup:** Fail one slot on a join error, not the whole boot
- **vpn:** Emit the adoption ground as a token, not a sentence
- **http:** Apply RFC 7239 quoting only where a grammar defines it
- **http:** Answer the scheme from the whole chain under either header name
- **http:** Unmap the socket peer once, before the trust test
- **http:** Match a v4-mapped trusted_proxies entry against the peer it names
- **config:** Refuse libtorrent's default prefix as an effective identity
- **config:** A profile's store directories are not an identity a tracker sees
- **config:** Report that a reloadable key differed, not just its value
- **config:** Run the boot rule with the rest of the shape checks
- **config:** Bound upload_rate_limit at i32::MAX
- **startup:** Tear down tunnels and kill switch when the HTTP bind fails
- **config:** Refuse the kill switch beside an OpenVPN slot
- **vpn-check:** Let an answered handshake outrank the link type, and route slot checks through CheckHost
- **config:** Refuse network_kill_switch beside a host profile
- **http:** Refuse a delete that races an add's AddTorrent alert
- **startup:** Disable a vpn profile whose tunnel shares another's address
- **pool:** Release the registry claim of a verify the worker drops
- **startup:** Claim a tunnel address only once its profile's session is up
- **http:** Read If-None-Match across every field line
- **http:** Log the effective trust set at startup, and fix a dead doc link
- **auth:** Cap password verifications daemon-wide across every bucket
- **killswitch:** Detect a missing nftables table from the listing, not localised nft stderr ([#49](https://github.com/d18580b/torrent/pull/49))
- **profile:** Validate vpn_interface's shape and refuse unquotable names in the kill-switch ruleset ([#51](https://github.com/d18580b/torrent/pull/51))
- **startup:** Refuse a second daemon before it touches the running one's kill switch ([#53](https://github.com/d18580b/torrent/pull/53))
- **profile:** [**breaking**] Replace peer_fingerprint_hex with the raw 8-character peer_fingerprint ([#55](https://github.com/d18580b/torrent/pull/55))
- **vpn:** Run the kill switch with a WireGuard tunnel the daemon raises itself ([#60](https://github.com/d18580b/torrent/pull/60))
- **engine:** [**breaking**] Make the disk-error retry recover what libtorrent actually left, and name it for that ([#61](https://github.com/d18580b/torrent/pull/61))
- Never download — force upload_mode on every add, and keep the engine honest under load ([#82](https://github.com/d18580b/torrent/pull/82))
- Harden resume, drain and teardown ordering for 100K-torrent shutdown and startup ([#88](https://github.com/d18580b/torrent/pull/88))
- Ops, deploy, config and CI hardening (W9) ([#87](https://github.com/d18580b/torrent/pull/87))
- **http:** [**breaking**] Harden the /v1 HTTP and auth surface ([#86](https://github.com/d18580b/torrent/pull/86))
- **port-forward:** Confirm a NAT-PMP rebind on listen_succeeded before reporting it ([#89](https://github.com/d18580b/torrent/pull/89))
- [**breaking**] One tracker guard on every add path, required on vpn profiles ([#91](https://github.com/d18580b/torrent/pull/91))
- **pool:** [**breaking**] Never delete or adopt the wrong payload ([#90](https://github.com/d18580b/torrent/pull/90))
- **vpn:** Route and handshake fencing, per-source routing, atomic kill switch, NAT-PMP fixes ([#84](https://github.com/d18580b/torrent/pull/84))
- **http:** Refuse trusted_proxies entries whose effective prefix is /0 ([#98](https://github.com/d18580b/torrent/pull/98))
- **config:** Refuse per-profile resume_dir and torrent_dir inside a pool root ([#125](https://github.com/d18580b/torrent/pull/125))
- **vpn:** Accept each profile's tunnel only from its own address ([#127](https://github.com/d18580b/torrent/pull/127))
- **startup:** Start the VPN monitor before the boot scans ([#130](https://github.com/d18580b/torrent/pull/130))
- **vpn:** Pause torrents a fence catches mid-add ([#132](https://github.com/d18580b/torrent/pull/132))
- **vpn:** Clean up network state an unclean exit leaves behind ([#133](https://github.com/d18580b/torrent/pull/133))
- **pool:** Clear the adopted state when nothing holds the torrent ([#138](https://github.com/d18580b/torrent/pull/138))
- **pool:** Keep a fastresume's trackers on verify-path adoption ([#137](https://github.com/d18580b/torrent/pull/137))
- **vpn:** Verify the kill-switch ruleset and fence while it is lost ([#141](https://github.com/d18580b/torrent/pull/141))
- **api:** Trash delete_files payload and require confirm ([#142](https://github.com/d18580b/torrent/pull/142))
- **pool:** Persist adopted torrents' .torrent so a restart keeps their metadata ([#145](https://github.com/d18580b/torrent/pull/145))
- **pool:** Run a drift pass over an adopt's selection before planning it ([#149](https://github.com/d18580b/torrent/pull/149))
- **api:** Reload an API-added torrent at its own save path when its resume file is missing ([#148](https://github.com/d18580b/torrent/pull/148))
- **pool:** Record an adopted torrent's save path beside its .torrent ([#153](https://github.com/d18580b/torrent/pull/153))
- **vpn:** Tear down a retired OpenVPN profile's state at boot ([#152](https://github.com/d18580b/torrent/pull/152))
- **killswitch:** Scope the transport exemption to the provider endpoint, follow the link, and fence tunnel addresses ([#154](https://github.com/d18580b/torrent/pull/154))
- **pool:** Keep adoptions waiting for verification across a restart ([#155](https://github.com/d18580b/torrent/pull/155))
- **vpn:** Release a retired OpenVPN profile's records in net-cleanup ([#162](https://github.com/d18580b/torrent/pull/162))
- **api:** Refuse a same-profile claim instead of sharing it ([#233](https://github.com/d18580b/torrent/pull/233))
- **vpn:** Count kill-switch losses the watch reinstalls, and alert on them ([#235](https://github.com/d18580b/torrent/pull/235))
- **vpn:** Bind vpn listen sockets to the tunnel device and stop on a wrong binding ([#234](https://github.com/d18580b/torrent/pull/234))
- **api:** Keep a re-added torrent's files and entry from a late removal ([#240](https://github.com/d18580b/torrent/pull/240))
- **vpn:** Do not fence a profile when `ip` cannot run in the tunnel probe ([#241](https://github.com/d18580b/torrent/pull/241))
- **vpn:** Fence ipv6 tunnel addresses, and source-route openvpn's ipv6 address ([#242](https://github.com/d18580b/torrent/pull/242))
- **vpn:** Revert a failed nat-pmp rebind instead of exiting on the only session ([#244](https://github.com/d18580b/torrent/pull/244))
- **vpn:** Judge a wireguard handshake's age only while its profile has traffic to carry ([#246](https://github.com/d18580b/torrent/pull/246))
- **pool:** Record an adoption's verdict across a restart mid-verify ([#247](https://github.com/d18580b/torrent/pull/247))
- **pool:** Recheck a relocate destination at apply and catch skipped files ([#249](https://github.com/d18580b/torrent/pull/249))
- **pool:** Count a directory the scan cannot list as a walk error ([#250](https://github.com/d18580b/torrent/pull/250))
- **vpn:** Name the kill-switch table per uid, and remove only this uid's ([#253](https://github.com/d18580b/torrent/pull/253))
- **api:** Refuse delete_files when another loaded torrent has a file at the same path ([#256](https://github.com/d18580b/torrent/pull/256))
- **vpn:** Pace bulk resumes like the port-change reannounce ([#252](https://github.com/d18580b/torrent/pull/252))
- **vpn:** Warn when two profiles share a WireGuard Endpoint, and document per-account exits ([#257](https://github.com/d18580b/torrent/pull/257))
- **pool:** Record verify verdicts after releasing the queue locks ([#258](https://github.com/d18580b/torrent/pull/258))
- **logging:** Hold tracker warning lines to host-only URL redaction ([#260](https://github.com/d18580b/torrent/pull/260))
- **api:** Refuse cross-site and DNS-rebound requests to an unauthenticated daemon ([#261](https://github.com/d18580b/torrent/pull/261))
- **vpn:** Pause a single resume again when its profile is fenced meanwhile ([#262](https://github.com/d18580b/torrent/pull/262))
- **vpn:** Refuse the root kill switch in the pre-flight, exiting 78 before any tunnel is raised ([#263](https://github.com/d18580b/torrent/pull/263))
- **pool:** Treat registry and verify-queue torrents as owned when applying plans ([#265](https://github.com/d18580b/torrent/pull/265))
- **api:** Refuse delete_files on a boot-unloaded torrent and clear its stores ([#266](https://github.com/d18580b/torrent/pull/266))
- **api:** Run adoptions and plan creation without the 30 s deadline, and close the adopt dialog on a 408 ([#268](https://github.com/d18580b/torrent/pull/268))
- **vpn:** Start the kill-switch watch at boot so a ruleset flushed during the scans is fenced ([#270](https://github.com/d18580b/torrent/pull/270))
- **pool:** Refuse a relocate the session holds away from its source and confirm the payload arrived ([#271](https://github.com/d18580b/torrent/pull/271))
- **engine:** Add every magnet with DHT, PEX and LSD disabled ([#273](https://github.com/d18580b/torrent/pull/273))
- **pool:** Keep a held torrent adopted when a rescan finds its payload partial or gone ([#276](https://github.com/d18580b/torrent/pull/276))
- **api:** Answer 500 internal, not 409 torrent-exists, when an add cannot write the assignment registry ([#279](https://github.com/d18580b/torrent/pull/279))
- **startup:** Re-add a claimed torrent with no resume file at its recorded save path ([#277](https://github.com/d18580b/torrent/pull/277))
- **pool:** Refuse roots that alias one tree, and deletes of a claimed file's other paths ([#278](https://github.com/d18580b/torrent/pull/278))
- **api:** Copy only the requested page of a file listing under the session lock ([#281](https://github.com/d18580b/torrent/pull/281))
- **metrics:** Hold listen_failure_active at 1 while any of a profile's sockets is failed ([#280](https://github.com/d18580b/torrent/pull/280))
- **pool:** Refuse a CLI pool scan beside the daemon, and never run an unjournalled plan step ([#282](https://github.com/d18580b/torrent/pull/282))
- **metrics:** Export what a boot counted as gauges so its alerts fire ([#283](https://github.com/d18580b/torrent/pull/283))
- **pool:** Bound POST /v1/pool/verifications re-hashes by max_concurrent_verify ([#289](https://github.com/d18580b/torrent/pull/289))
- **vpn:** Keep a wireguard private key out of a bring-up failure reason ([#287](https://github.com/d18580b/torrent/pull/287))
- **engine:** Keep every torrent tracked when a boot overflows libtorrent's alert queue ([#288](https://github.com/d18580b/torrent/pull/288))
- **pool:** Refuse a delete plan only for unclaimed torrents that may reach its root ([#290](https://github.com/d18580b/torrent/pull/290))
- **api:** Answer DELETE /v1/torrents without waiting out a running scan ([#293](https://github.com/d18580b/torrent/pull/293))
- **startup:** Signal shutdown on an HTTP bind or accept failure, and survive EMFILE in accept ([#294](https://github.com/d18580b/torrent/pull/294))
- **api:** Say a static token is revoked by a restart, not a reload ([#298](https://github.com/d18580b/torrent/pull/298))
- **pool:** Say an unknown-outcome step parks its plan for good, and record a move a stop cuts off ([#299](https://github.com/d18580b/torrent/pull/299))
- **pool:** Prefer a loaded torrent's session save_path over its recorded base on rescan ([#301](https://github.com/d18580b/torrent/pull/301))
- **api:** Check the credential before a /v1 body is read, and bound the apply body ([#302](https://github.com/d18580b/torrent/pull/302))
- **pool:** Give every delete plan a trash directory a restore cannot repeat ([#303](https://github.com/d18580b/torrent/pull/303))
- **profile:** Keep two accounts on one tracker apart with allowed_tracker_urls ([#306](https://github.com/d18580b/torrent/pull/306))
- **pool:** Count a boot re-drive that times out waiting for the state map ([#307](https://github.com/d18580b/torrent/pull/307))
- **engine:** Save resume data at once after a recheck, a relocate or a pause ([#309](https://github.com/d18580b/torrent/pull/309))
- **api:** Let a client that has logged in before past a spent login budget ([#310](https://github.com/d18580b/torrent/pull/310))
- **engine:** Stop warning on and counting tracker errors a pause or stop causes ([#314](https://github.com/d18580b/torrent/pull/314))
- **pool:** Page plan steps and batch the apply journal ([#312](https://github.com/d18580b/torrent/pull/312))
- **engine:** Make DELETE of a torrent durable, with a tombstone the boot honours ([#313](https://github.com/d18580b/torrent/pull/313))
- **reload:** Log the full error chain when a SIGHUP reload fails ([#318](https://github.com/d18580b/torrent/pull/318))
- **vpn:** Run openvpn with --script-security 1 and refuse a hooked .ovpn ([#316](https://github.com/d18580b/torrent/pull/316))
- **engine:** Mark a DiskError torrent Checking before an operator or pool recheck ([#321](https://github.com/d18580b/torrent/pull/321))
- **startup:** Extend the boot start timeout while the boot makes progress ([#322](https://github.com/d18580b/torrent/pull/322))
- **vpn:** Pace the resume of a profile set online, and hold what the pace paused across a restart ([#320](https://github.com/d18580b/torrent/pull/320))
- **engine:** Hash-check API and torrent-dir adds before they seed ([#326](https://github.com/d18580b/torrent/pull/326))
- **startup:** Count only newly paused scan torrents when a fence record vanishes ([#325](https://github.com/d18580b/torrent/pull/325))
- **pool:** Release a paced hold when the operator resumes its torrent ([#327](https://github.com/d18580b/torrent/pull/327))
- **metrics:** Export the rest of what a boot counts as gauges so its alerts fire ([#330](https://github.com/d18580b/torrent/pull/330))
- **api:** Prove a delete_files payload from one read of the committed pool index ([#334](https://github.com/d18580b/torrent/pull/334))
- **torrentd:** Save resume data at once after a bulk pause ([#335](https://github.com/d18580b/torrent/pull/335))
- **startup:** Log the full cause chain of three boot-path anyhow errors ([#336](https://github.com/d18580b/torrent/pull/336))
- **metrics:** Export the boot's pool-plan, storage-move and dropped-sample counts as gauges ([#339](https://github.com/d18580b/torrent/pull/339))
- **vpn:** Refuse the openvpn genkey directive, which writes a file the config names ([#340](https://github.com/d18580b/torrent/pull/340))
- **api:** Serialise a hand resume's hold release against a paced set-online ([#338](https://github.com/d18580b/torrent/pull/338))
- **vpn:** Judge a stale wireguard handshake on traffic nothing answered ([#342](https://github.com/d18580b/torrent/pull/342))
- **engine:** Lift a magnet's discovery guards once its metadata shows it is public ([#343](https://github.com/d18580b/torrent/pull/343))
- **vpn:** Refuse the openvpn directives that load a shared library ([#360](https://github.com/d18580b/torrent/pull/360))
- **vpn:** Keep torrents paused during a kill-switch fence or by a failed verification out of the lift ([#362](https://github.com/d18580b/torrent/pull/362))
- **pool:** Hold a queued re-hash while a fence's lift has yet to resume its torrent ([#361](https://github.com/d18580b/torrent/pull/361))
- **ffi:** Return torrent file paths and save paths whole instead of cutting them at 1023 bytes ([#367](https://github.com/d18580b/torrent/pull/367))
- **deploy:** Alert on boot save-path fallbacks and remove-cleanup errors, and on verify failures before the first scrape ([#371](https://github.com/d18580b/torrent/pull/371))
- **vpn:** Record what the add paths pause under a kill-switch fence for its lift ([#369](https://github.com/d18580b/torrent/pull/369))
- **ffi:** Carry the storage_moved_alert save path whole instead of cutting it at 1023 bytes ([#372](https://github.com/d18580b/torrent/pull/372))
- **metrics:** Catalogue listen_accept_errors_total and document it in deploy/metrics.md ([#375](https://github.com/d18580b/torrent/pull/375))
- **docs:** Back up library_dir, correct the healthz migration note, and make the compose payload mount writable by uid 1000 ([#374](https://github.com/d18580b/torrent/pull/374))
- **vpn:** Count boot-scan torrents under a monitor fence that follows a kill-switch lift ([#376](https://github.com/d18580b/torrent/pull/376))
- **engine:** Settle removals whose torrent_removed_alert an alert overflow dropped ([#377](https://github.com/d18580b/torrent/pull/377))
- **vpn:** Fail safe on the stale-handshake fence while the transfer probe fails ([#378](https://github.com/d18580b/torrent/pull/378))
- **vpn:** Skip a kill-switch lift verdict taken before the profile was fenced again ([#381](https://github.com/d18580b/torrent/pull/381))
- **observability:** Evaluate TorrentdTrackerErrors per instance and log the errno of a fatal HTTP server failure ([#382](https://github.com/d18580b/torrent/pull/382))
- **http:** Refuse a plain DELETE of an unloaded torrent whose resume or .torrent file remains ([#380](https://github.com/d18580b/torrent/pull/380))
- **http:** Bound single rechecks with the verify queue and correct what max_concurrent_verify covers ([#384](https://github.com/d18580b/torrent/pull/384))
- **engine:** Key a hybrid torrent by one stable info-hash ([#248](https://github.com/d18580b/torrent/pull/248))
- **vpn:** Set profile_vpn_tunnel_up to 0 on every fence, so a kill-switch fence its lift leaves standing alerts ([#398](https://github.com/d18580b/torrent/pull/398))
- **vpn:** Disable openvpn 2.7's built-in dns-updown script without breaking 2.6 ([#400](https://github.com/d18580b/torrent/pull/400))
- **engine:** Pause again a torrent the disk-error retry resumed as its profile was fenced ([#401](https://github.com/d18580b/torrent/pull/401))
- **api:** Let the retry of a delete that could not clear the assignment clear it ([#404](https://github.com/d18580b/torrent/pull/404))
- **pool:** Refuse to relocate an unloaded torrent a loaded one still serves files from ([#402](https://github.com/d18580b/torrent/pull/402))
- **deploy:** Alert on kill-switch, port-forward and accept failures counted during the boot ([#406](https://github.com/d18580b/torrent/pull/406))
- **pool:** Reconcile a pool-index owner record whose DELETE release was lost ([#403](https://github.com/d18580b/torrent/pull/403))
- **engine:** Refresh every torrent's status after an overflow drops a state update ([#405](https://github.com/d18580b/torrent/pull/405))
- **deploy:** Say set-online lifts a fence in the tunnel-up panel, not a restart ([#409](https://github.com/d18580b/torrent/pull/409))
- **vpn:** Read a pause or resume no state update has reported yet when the fence or a set-online decides what runs ([#411](https://github.com/d18580b/torrent/pull/411))
- **startup:** Refuse a torrent filed under another key than its session gives it ([#413](https://github.com/d18580b/torrent/pull/413))
- **engine:** Bound every hash check by one daemon-level check queue ([#414](https://github.com/d18580b/torrent/pull/414))
- **pool:** Note a failed verification's pause before a fence can read it ([#415](https://github.com/d18580b/torrent/pull/415))
- **vpn:** Count a boot-scan torrent once per fence when the fence and the scans both pause it ([#416](https://github.com/d18580b/torrent/pull/416))
- **pool:** Rewrite a pool-index owner the registry contradicts at boot ([#417](https://github.com/d18580b/torrent/pull/417))
- **startup:** Refuse resume data whose session key cannot be read before the add ([#419](https://github.com/d18580b/torrent/pull/419))
- **vpn:** Stop a replaced paced resume from resuming a lifted fence's torrents twice ([#486](https://github.com/d18580b/torrent/pull/486))
- **deploy:** Give the systemd unit a runtime directory for the API socket ([#492](https://github.com/d18580b/torrent/pull/492))
- **vpn:** Keep a resume that races a kill-switch fence in its record ([#497](https://github.com/d18580b/torrent/pull/497))
- **torrentd:** Startup and reload edge cases (rekey claim loss, reload descriptor check, lagged shutdown, per-profile torrent_dir adds) ([#494](https://github.com/d18580b/torrent/pull/494))
- **engine:** Per-profile resume requeue, DB-only registry removes, counted unknown alerts ([#499](https://github.com/d18580b/torrent/pull/499))
- **pool:** Never seed unverified data from a short fastresume bitfield ([#516](https://github.com/d18580b/torrent/pull/516))
- **vpn:** Keep the VPN monitor and kill-switch watch fencing through the shutdown drain ([#518](https://github.com/d18580b/torrent/pull/518))
- **pool:** Close the plan races of delete during apply, a racing apply, and refused re-drives ([#523](https://github.com/d18580b/torrent/pull/523))
- **vpn:** Give IPv6 the same route probe and kill-switch address refresh as IPv4 ([#535](https://github.com/d18580b/torrent/pull/535))
- **torrentd:** Refuse to start a fault-injection build unless explicitly enabled ([#526](https://github.com/d18580b/torrent/pull/526))
- **pool:** Keep a fenced adoption or a running scan from stalling the check queue, and report the adopt bucket taken ([#532](https://github.com/d18580b/torrent/pull/532))
- **pool:** Fail safe on an unreadable or unmounted root and an unlistable subtree ([#531](https://github.com/d18580b/torrent/pull/531))
- **vpn:** Ask the IPv6 route probe in vpn check and at WireGuard bring-up ([#538](https://github.com/d18580b/torrent/pull/538))
- **torrentd:** Keep boot responsive, check listen devices before the scans add, read scan files lazily ([#539](https://github.com/d18580b/torrent/pull/539))
- **vpn:** Fence profiles whose health checks persistently cannot run ([#542](https://github.com/d18580b/torrent/pull/542))
- **pool:** Re-check a delete plan's ownership by change counter, not sizes ([#545](https://github.com/d18580b/torrent/pull/545))
- **torrentd:** Hold every vpn session's listen sockets at each scan batch ([#550](https://github.com/d18580b/torrent/pull/550))
- **http:** Make the event fingerprint cover every state a client renders ([#547](https://github.com/d18580b/torrent/pull/547))
- **pool:** Make relocate and trash steps exact ([#554](https://github.com/d18580b/torrent/pull/554))
- **torrentd:** Refuse a second daemon that would share the per-uid kill-switch table ([#559](https://github.com/d18580b/torrent/pull/559))
- **http:** Keep the event feed's pending state read across feed restarts ([#563](https://github.com/d18580b/torrent/pull/563))
- **engine:** Re-assert upload mode when a status shows it lapsed, and count each re-assert ([#562](https://github.com/d18580b/torrent/pull/562))
- **pool:** List unclaimed top-level files in pool orphans ([#573](https://github.com/d18580b/torrent/pull/573))
- **pool:** Keep literal backslash names and the library read cap in the daemon's pool paths ([#574](https://github.com/d18580b/torrent/pull/574))
- **engine:** Start a just-added torrent in the phase its metadata implies, not idle ([#569](https://github.com/d18580b/torrent/pull/569))
- **pool:** Count symlinks skipped under a pool root as scan errors ([#590](https://github.com/d18580b/torrent/pull/590))
- **apply:** Fsync directories created for the trash and relocate parents ([#624](https://github.com/d18580b/torrent/pull/624))
- **check-queue:** Free an adoption slot whose torrent_checked alert was lost ([#621](https://github.com/d18580b/torrent/pull/621))
- **torrentd:** Refuse a delete plan while a claimed torrent saves away from its placement ([#625](https://github.com/d18580b/torrent/pull/625))
- **torrentd:** Give every test state a registry database no earlier run used ([#635](https://github.com/d18580b/torrent/pull/635))
- **http:** Hold one reload in the queue so a second request is 409 ([#638](https://github.com/d18580b/torrent/pull/638))
- **pool:** Drop the top directory of a one-file NoSubfolder torrent ([#637](https://github.com/d18580b/torrent/pull/637))
- **pool:** Refuse an adoption whose library .torrent no longer names the indexed torrent ([#640](https://github.com/d18580b/torrent/pull/640))
- **torrentd:** Persist a magnet's URI so a restart before its first save re-adds it ([#643](https://github.com/d18580b/torrent/pull/643))
- **torrentd:** Keep a kill-switch fence while the table is not in force ([#646](https://github.com/d18580b/torrent/pull/646))
- **torrentd:** Retry the kill-switch reinstall with backoff while the table stays lost ([#647](https://github.com/d18580b/torrent/pull/647))
- **torrentd:** Hold queued adoptions of a profile that failed to start ([#665](https://github.com/d18580b/torrent/pull/665))
- **torrentd:** Fail an error-paused adoption and free its verify slot ([#664](https://github.com/d18580b/torrent/pull/664))
- **torrentd:** Fsync a relocated payload before its step is recorded done ([#666](https://github.com/d18580b/torrent/pull/666))
- **torrentd:** Keep declared empty files out of orphans, trash them on delete, catch aliased payload ([#668](https://github.com/d18580b/torrent/pull/668))
- **torrentd-pool:** Hash skip-hash-check torrents instead of fast-pathing them ([#673](https://github.com/d18580b/torrent/pull/673))
- **torrentd:** Save resume data when an adoption verification passes ([#675](https://github.com/d18580b/torrent/pull/675))
- **torrentd:** Re-add an adopted torrent with its trackers, and take the library .torrent over an unreadable one ([#676](https://github.com/d18580b/torrent/pull/676))
- **torrentd:** Refuse a target whose adoption records fail to commit ([#678](https://github.com/d18580b/torrent/pull/678))
- **torrentd:** Let a delete through after a reboot renumbers device and inode ([#680](https://github.com/d18580b/torrent/pull/680))
- **torrentd:** Refuse a delete only when a claimed file is the same file now ([#687](https://github.com/d18580b/torrent/pull/687))
- **torrentd-pool:** Look up claimed files by an orphan's live identity too ([#693](https://github.com/d18580b/torrent/pull/693))

### Performance

- **vpn:** Keep blocking tunnel I/O off the runtime's worker threads
- **startup:** Keep the bounded teardown wait off the runtime's workers
- **startup:** Stop the drain scaling with the slot count
- **startup:** Sweep raised-interface records off the runtime worker
- **pool:** [**breaking**] Keep the daemon responsive through hour-long scans ([#92](https://github.com/d18580b/torrent/pull/92))
- **torrentd:** Bound bulk adoption latency ([#604](https://github.com/d18580b/torrent/pull/604))
- **torrentd:** Look up each claim's bases instead of scanning every file ([#644](https://github.com/d18580b/torrent/pull/644))

### Refactored

- Rename seederd to torrentd
- [**breaking**] Rename slots to profiles
- **http:** Return app_state's doc comment to the item it describes
- **startup:** Raise and tear down a tunnel with the same manager
- **signals:** Drop the reload seam that could not carry a reload
- **startup:** Delete the blocking teardown, not its call sites
- **startup:** Route every teardown in boot through the one helper
- **vpn-check:** Put host_checks behind the CheckHost seam
- **config:** Narrow validate_without_auth_posture to the crate
- **config:** Make diff's completeness a compile-time property
- **main:** Make the operator-tool exemption an allow-list
- **config:** Classify a profile change where it is compared
- **startup:** Share boot's run directory with the shutdown teardown
- **config:** Make an uncompared ProfileConfig field stop compiling
- **config:** Derive the reloadable-key predicates from the patch
- **vpn-check:** Partition profiles rather than id pairs in the ruleset attribution
- [**breaking**] De-slop redundant code, comments and tests ([#96](https://github.com/d18580b/torrent/pull/96))
- Move torrentd-only engine code to torrentd and split alert_loop.rs ([#578](https://github.com/d18580b/torrent/pull/578))
- **torrentd:** Split startup.rs along its responsibilities ([#576](https://github.com/d18580b/torrent/pull/576))
- **torrentd:** Split vpn_monitor.rs, give the fence its own module, move vpn tests beside their code ([#592](https://github.com/d18580b/torrent/pull/592))
- **torrentd:** Split pool_service.rs into check_queue/ and torrent_keys ([#597](https://github.com/d18580b/torrent/pull/597))
- **torrentd:** Split pool_apply.rs into apply/, pool_trash and live_torrent ([#599](https://github.com/d18580b/torrent/pull/599))
- **torrentd:** Split torrents handlers and oversized torrentd test files ([#606](https://github.com/d18580b/torrent/pull/606))

### Documentation

- Delete the PRD
- Rewrite the README for users
- Say what an empty trusted_proxies actually does to the throttle
- **wireguard:** Record what tunnel adoption does and does not vouch for
- Undo five rename substitutions that crossed a semantic boundary
- Retire the mode vocabulary this model deletes
- Correct the upgrade note and the API paths it cites
- **auth:** Separate the Write scope from the allow_mutations switch
- **http:** Name Forwarded among the headers a trusted proxy must strip
- Count the failed-login log line among what the client address feeds
- **reload:** Name the two reloadable keys that do not reach every session
- **vpn-check:** State what a pass establishes, and that --bring-up needs root
- **deploy:** Set http_listen explicitly in the compose stack
- **auth:** State where the Argon2 cost is pinned, not who recommends it
- **config:** List `[auth]` in §5, and record the refusal's position
- **config:** Say which half of the diff invariant is a build error
- **auth:** Give the allow_mutations boundary the reason the source gives
- **vpn:** State which tunnel shapes the kill switch can run with
- **config:** Stop claiming compose sets http_listen explicitly
- **http:** Stop ui.rs claiming the shipped proxy caches the bundle
- **tracing:** Correct log shape in tracing_init module doc ([#48](https://github.com/d18580b/torrent/pull/48))
- Settle #24's remaining VPN audit items (PATH trust, --check-config scope, kill switch replies, UploadMode) ([#47](https://github.com/d18580b/torrent/pull/47))
- Make the docs and comments true ([#95](https://github.com/d18580b/torrent/pull/95))
- Fix doc/code mismatches in running.md, compose, kill-switch docs and README ([#151](https://github.com/d18580b/torrent/pull/151))
- **metrics:** Say a kill-switch probe error is a check that could not run ([#160](https://github.com/d18580b/torrent/pull/160))
- **deploy:** Give the sample profiles libtorrent-based client identities ([#269](https://github.com/d18580b/torrent/pull/269))
- **api:** Fix the PATCH, torrent-adding, confirm-token and torrent-not-found contradictions ([#286](https://github.com/d18580b/torrent/pull/286))
- **api:** Say a failed plan with an in_progress step is never applied again ([#308](https://github.com/d18580b/torrent/pull/308))
- Remove stale, orphaned, and pre-profiles material ([#491](https://github.com/d18580b/torrent/pull/491))
- Keep one authoritative copy of each duplicated doc claim ([#519](https://github.com/d18580b/torrent/pull/519))
- **running:** Correct VPN runbook and deploy comments that contradict the daemon ([#589](https://github.com/d18580b/torrent/pull/589))
- **torrentd:** State the benched scale in --help and the package description ([#603](https://github.com/d18580b/torrent/pull/603))
- **torrentd:** Make doc comments match the code after the split ([#608](https://github.com/d18580b/torrent/pull/608))

### Tests

- **torrentd:** Give each test state its own registry file
- **killswitch:** Reach the uid-0 refusal the guard actually consults
- **vpn-check:** Cover the JSON contract and check()'s two bails
- **killswitch:** Reach the uid-0 guard's call site, not just its predicate
- **startup:** Pin the receivers-before-listener order
- **killswitch:** Inject the pre-clear, not just the apply
- **startup:** Assert the teardown overlap rather than time it
- **startup:** Widen the one-teardown-shape gate to the whole crate
- **config:** Build the shared fixture the way its comment says
- **startup:** Count the teardown census over the code that ships
- **vpn:** Pin the two ownership rows a record is now matched against
- **config:** Expect Config::load to refuse a kill switch beside a host profile
- **startup:** Count vpn check's teardown as a documented bring_down site
- **startup:** Drive per-profile session construction with mocks ([#43](https://github.com/d18580b/torrent/pull/43))
- **config:** Cover diff_profiles per field, no-op, and reloadable-key isolation ([#44](https://github.com/d18580b/torrent/pull/44))
- **torrentd:** Stop redaction fixture tripping the tracing field-name lint ([#66](https://github.com/d18580b/torrent/pull/66))
- **drill:** Drill the kill-switch and port-forward edges, and re-check the fence mid-renewal ([#134](https://github.com/d18580b/torrent/pull/134))
- **daemon:** Capture the scale test's daemon output and name the last /healthz answer ([#370](https://github.com/d18580b/torrent/pull/370))
- **auth:** Drive the verification budget refill test on the fake clock ([#399](https://github.com/d18580b/torrent/pull/399))
- **vpn:** Run the real-kernel VPN tests in a privileged netns CI job ([#496](https://github.com/d18580b/torrent/pull/496))
- Prove a qBittorrent BT_backup import end to end, pool and daemon ([#503](https://github.com/d18580b/torrent/pull/503))
- **http:** Pin the connection bounds kynos 0.4 changed ([#504](https://github.com/d18580b/torrent/pull/504))
- Prove crash recovery under SIGKILL and pin the durable-write order ([#509](https://github.com/d18580b/torrent/pull/509))
- **torrentd:** Pin auth, session, throttle, reload and alert-counter behaviour ([#540](https://github.com/d18580b/torrent/pull/540))
- **torrentd:** Tighten tests that ran without constraining, or coupled to private details ([#566](https://github.com/d18580b/torrent/pull/566))
- State the code's laws as property tests (proptest, dev-only) ([#571](https://github.com/d18580b/torrent/pull/571))
- State the remaining #435 laws as property tests ([#580](https://github.com/d18580b/torrent/pull/580))
- **bench:** Measure pool scan, match and adopt preview at scale against recorded budgets ([#596](https://github.com/d18580b/torrent/pull/596))
- Pin a second tracing dispatcher in every event-capturing test ([#602](https://github.com/d18580b/torrent/pull/602))
- Pin a second tracing dispatcher in every set_default log-capture test ([#607](https://github.com/d18580b/torrent/pull/607))
- Squash surviving mutants in the safety-critical modules ([#615](https://github.com/d18580b/torrent/pull/615))
- **torrentd:** Assert row and fsync counts, not wall time, for 100K assigns ([#636](https://github.com/d18580b/torrent/pull/636))
- Squash surviving mutants in fence, vpn_monitor and the rest of auth.rs ([#645](https://github.com/d18580b/torrent/pull/645))
- **torrentd:** Name this process as the table lock's holder deterministically ([#648](https://github.com/d18580b/torrent/pull/648))

### Build

- **torrentd:** Watch precompress.mjs, and record two consequences it has

### CI

- Clear clippy 1.99 lints on stable ([#94](https://github.com/d18580b/torrent/pull/94))
- **release:** Cut signed releases with release-plz ([#598](https://github.com/d18580b/torrent/pull/598))

### Chores

- Merge feat/vpn-check into feat/profiles
- **docs:** Merge feat/reverse-proxy into docs/truth-pass
- Merge feat/vpn-check into feat/profiles
- **deps:** Migrate to kynos 0.4 ([#488](https://github.com/d18580b/torrent/pull/488))

### Merge

- Bring feat/vpn-check into feat/profiles
- Bring feat/secure-by-default into feat/reverse-proxy
- Bring feat/reverse-proxy into docs/truth-pass
- Bring feat/secure-by-default into feat/reverse-proxy
- Bring feat/reverse-proxy into docs/truth-pass

