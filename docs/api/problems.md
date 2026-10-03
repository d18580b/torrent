# Problem types

Every `4xx` and `5xx` response from the `/v1` API is an [RFC 9457] problem
document, `application/problem+json`:

```json
{
  "type": "https://github.com/d18580b/torrent/blob/master/docs/api/problems.md#profile-unavailable",
  "title": "The profile is unavailable",
  "status": 409,
  "detail": "profile vpn_down; restart daemon to resume",
  "profile_status": "vpn_down"
}
```

- **`type`** identifies the failure. It is stable for the life of `/v1`, and it
  resolves to the heading for it below. Branch on `type`, never on `detail`.
- **`title`** is a short, fixed summary of the type.
- **`status`** repeats the HTTP status.
- **`detail`** explains this occurrence, in prose meant for an operator. Its
  wording may change.
- **Extension members** such as `profile_status` are listed under the type
  that carries them.

The published document narrows each response's `type` to the values that
operation can produce, so a generated client knows exactly which failures to
expect from each call.

Every problem a handler or the framework's validation returns also carries
`X-Request-Id`. The daemon's trace line for the response carries it; quote
it when reporting a failure.

## Failures the framework reports

A few failures are detected before any handler runs, and are reported with
`"type": "about:blank"`. RFC 9457 defines that value as meaning the HTTP status
says everything there is to say:

| Status | When |
| --- | --- |
| `400` | A path parameter, a query parameter or a JSON body that does not parse. |
| `401` | No bearer token, or one that is unknown, expired or revoked. `WWW-Authenticate: Bearer` accompanies it. |
| `404` | No route matches the path. |
| `405` | The route exists, but not for this method. |
| `408` | An operation that takes a body did not receive it and answer within its deadline (30 seconds, or 300 for `POST /v1/torrents`). Effects already started are not undone: an add may still complete, and a pool verification's rechecks may still start. |
| `413` | The request body is over the operation's limit (64 KiB, or 96 MiB for `POST /v1/torrents`). |
| `415` | A body whose `Content-Type` is not `application/json`. |
| `422` | A JSON body of the wrong shape: a missing field, an unknown field, or a value of the wrong type. |

A body that parses but breaks a documented constraint, such as a value out of
range, is a [`validation-failed`](#validation-failed) instead, which says which
constraint and where.

## `insufficient-scope`

**403.** The credential is valid, but it was not issued the scope this
operation needs. Every operation names its scope in its `security`
requirement:

- **`read`** covers every safe operation.
- **`write`** covers every operation that changes state, and implies `read`.
- **`metrics`** covers `GET /metrics` and nothing else.

A session token carries `read` and `write`. A static token carries whatever
the config grants it.

## `auth-not-configured`

**409**, from `POST /v1/sessions`. The daemon runs with
`allow_unauthenticated = true` and no `[auth]`, so there is no password to
check and no session to create. Every operation already admits the request
without a credential.

## `invalid-credentials`

**401**, from `POST /v1/sessions`. The password is wrong. Nothing more is
said.

## `login-throttled`

**429**, from `POST /v1/sessions`. There are two causes: too many failed
attempts from this client, or a spent daemon-wide budget for the memory-hard
password hash. Either way, wait before trying again.

The wait is sent twice: in `Retry-After`, and in the `retry_after_secs`
extension member.

## `not-a-session`

**409**, from `DELETE /v1/sessions/current`. The presented credential is a
static token, or the daemon runs without authentication. Only a session token
can be revoked here. To revoke a static token, remove it from the config and
reload.

## `validation-failed`

**422.** The body or query parsed, but it breaks a constraint the document
declares, such as a `limit` outside `1..=1000` or a priority above 7.

`errors` lists every violation as `{ "pointer": …, "detail": … }`:

- A body member's `pointer` is an RFC 6901 JSON Pointer.
- A query parameter's `pointer` is `#/query/<name>`.

`detail` names the first violation and counts the rest.

## `invalid-cursor`

**400.** The `cursor` is not one this listing issued. It may be garbled, or it
may belong to a different listing. Start again without a cursor. A bad cursor
is never silently treated as the first page.

## `torrent-not-found`

**404.** No torrent with this infohash is assigned to any profile.

## `file-not-found`

**404**, from `PUT /v1/torrents/{infohash}/files/{index}/priority`. The torrent
has no file at this index.

## `profile-not-found`

**404.** No profile with this `profile_id` is configured.

## `root-not-found`

**404.** The pool has no managed root with this `root_id`.

## `plan-not-found`

**404.** The pool has no plan with this id.

## `pool-not-configured`

**404**, from every `/v1/pool` operation. The daemon has no `[pool]` section.
`GET /v1/server` reports this up front as `pool.configured`.

## `mutations-disabled`

**403.** The operation would change payload on disk, and `[pool]
allow_mutations` is off. `GET /v1/server` reports the switch as
`pool.allow_mutations`. It gates three things:

- creating a mutation plan
- applying a mutation plan
- `DELETE /v1/torrents/{infohash}?delete_files=true`

## `profile-unavailable`

**409.** The profile cannot take this request. The `profile_status` extension
member says why:

- **`failed`**: the profile never came up at boot, so its torrents are not
  loaded.
- **`vpn_down`**: the VPN monitor fenced the profile after its tunnel failed.
  It stays fenced until the daemon restarts, and nothing may un-quarantine it
  before then.

## `torrent-exists`

**409**, from `POST /v1/torrents`. A torrent with this infohash is already
assigned, to this profile or another. An infohash belongs to exactly one
profile.

## `torrent-adding`

**409**, from `DELETE /v1/torrents/{infohash}`. The torrent is still being
added to its session. Retry once it appears in `GET /v1/torrents`.

## `payload-shared`

**409**, from `DELETE /v1/torrents/{infohash}?delete_files=true`. The pool
index has another torrent claiming some of this torrent's files — a
cross-seed of the same payload, or a conflict — so deleting them would delete
that torrent's payload too. `detail` names the first. Retry without
`delete_files` to remove the torrent alone.

## `metadata-pending`

**409.** The torrent was added from a magnet URI and has not received its
metadata yet, so it has no file list. Retry once `name` appears on the torrent.

## `path-not-confined`

**422**, from `POST /v1/torrents`. A path in the request is outside the
directories the daemon may use:

- A `server_path` source must lie inside the daemon's `.torrent` store, the
  pool's library, or a managed root.
- A `save_path` must lie inside `default_save_path` or a managed root.

The detail never says whether the path exists.

## `invalid-metainfo`

**422**, from `POST /v1/torrents`. The magnet URI or `.torrent` could not be
parsed, or the `.torrent` could not be read.

## `tracker-not-allowed`

**422**, from `POST /v1/torrents`. The profile sets `allowed_tracker_domains`,
and the `.torrent` announces to none of them. This guards against adding one
account's torrent to another account's profile.

## `plan-refused`

**409**, from `POST /v1/pool/plans`. The planner refused the request, and
`detail` says why. For example, the destination is already occupied, or the
torrent is not in the index.

## `plan-applying`

**409**, from `DELETE /v1/pool/plans/{plan_id}`. The plan is mid-apply. It
will be resumed rather than discarded.

## `plan-not-draft`

**409**, from `POST /v1/pool/plans/{plan_id}/apply`. The plan cannot be
applied in its current status: it is `applying` (another request claimed it
first), `applied` or `cancelled`.

A `draft` plan can be applied. So can a `failed` one: re-applying it retries
the steps that did not complete.

## `apply-failed`

**409**, from `POST /v1/pool/plans/{plan_id}/apply`. The plan could not be
run at all, for example because the index could not be locked. `detail` names
the failure.

A run that starts and then stops on a failing step is **not** this problem.
It answers `200` with an `ApplyOutcome` whose `status` is `failed`, and the
plan's steps show how far it got. Apply it again to retry.

## `confirm-token-required`

**422**, from `POST /v1/pool/plans/{plan_id}/apply`. The plan deletes data, so
it applies only when `confirm_token` repeats the token the plan was created
with.

## `confirm-token-mismatch`

**422**, from `POST /v1/pool/plans/{plan_id}/apply`. The `confirm_token` is not
this plan's. Tokens are derived from the plan's steps, so a token cannot be
carried over from another plan.

## `reload-pending`

**409**, from `POST /v1/config/reload`. A reload is already queued and has not
run yet. The queued reload will read the same file.

## `reload-unavailable`

**503**, from `POST /v1/config/reload`. The reload task is not running.

## `internal`

**500.** Something failed inside the daemon, most often the torrent engine or
the pool index. `detail` says what was being attempted. The cause is logged at
`ERROR`, just before the trace line for the response, which carries its
`X-Request-Id`.

[RFC 9457]: https://www.rfc-editor.org/rfc/rfc9457
