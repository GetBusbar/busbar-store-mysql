# MySQL ordinary-test migration

Baseline: this repository `1376d0b`; busbar contract/loader pin stays
`a35493a5e74cc935ff7dcc15c1af869290da91cb`. The A discussion plan was read.
No applicable AGENTS.md exists in this checkout or its ancestors.

## Product assertions retained

`store-mysql-plugin/tests/conformance.rs` remains the cargo integration target.
Its original transcript, invalid/empty/missing/blank/unreachable URL arms,
Statement byte equality, wrong-kind and changed-Statement refusals, closed-root-port
error/deadline witness, and freshness-gate assertions remain.

`tests/support/store_contract.rs` expands the **exact pinned** store script into
ordinary blocks. No Subject, Recorder, Step, Fold, cross-kind routing, macro, kit,
or replacement Store implementation is retained. Each operation asserts its exact
first-invocation crossing delta on the actual loader's public doc-hidden atomic
counters (`crossings - resumes`), including leased-read release crossings. All
original contract goldens remain; linked/dropped results are compared. Ready is
explicitly awaited and counted; at least one network resume is required. Each arm
creates/grants its own database and drops/revokes it after completion. The 31-slot
compile-time assertion remains. The newer-schema test opens the real product,
stamps that database's schema to u32::MAX and requires a nonempty refusal through
**both** delivery paths (the former suite checked only linked).

The 86 pinned script labels map as follows: `facts` is the local facts read with
zero crossings; `refused as another kind` retains its inline exact zero-count Hook refusal
through each delivery, supplemented by all six wrong-kind admission tests;
`open` is the explicit successful LoadedStore open. All remaining labels are
ordinary blocks in `store_contract::exercise`, with unchanged pins and goldens:

`facts`, `refused as another kind`, `open`, `put grouped`, `put plain`, `get grouped`, `get absent`, `key list`, `delete plain`, `delete absent`, `relive plain`, `keys since 0`, `usage untouched`, `add usage`, `usage`, `put usage`, `usage j`, `usage again`, `meter p 3`, `meter p 4`, `meter q 1`, `metering`, `put k1`, `cred c1`, `cred c9 (live slot)`, `key+cred k2`, `creds k1`, `revoke c1`, `revoke absent`, `creds since`, `audit`, `audit tail 1`, `deny x`, `deny`, `upsert t1`, `get t1`, `append e1`, `append e2`, `append e2 fork`, `list ev t1`, `parents ev`, `purge ev`, `append rt1`, `append rt2`, `purge rt terminal-only`, `list rt kept`, `purge rt age`, `list rt aged`, `delete t1`, `get t1 after`, `upsert c1 under p`, `upsert c2 under p`, `get c1`, `list ctask p`, `delete c1`, `get c1 after`, `get c2`, `token live`, `redeem`, `redeem again`, `usage batch`, `usage batch replay`, `usage batch conflict`, `metering batch`, `record put a/1`, `record put a/2`, `record get`, `record get absent`, `record scan`, `record put a/1 empty`, `record get emptied`, `record scan emptied`, `typed upsert`, `typed get`, `typed append`, `typed list`, `typed delete`, `typed redeem`, `typed live`, `usage at the end`, `usage purge`, `usage purged`, `usage kept`, `scope-kind put`, `scope-kind get`, `scope-kind list`.

## Admission and host negative arms

`tests/support/door_refusals.rs` preserves kind ABI +/-1 (pack, linked and dropped
manifest exact errors); layout xor1/zero (pack and linked exact errors and rebuild
text); valid foreign-version Statement (linked row, dropped manifest and restated
door all mismatch); all six wrong kinds through both paths; missing connection
table through both paths with exact plugin/need count, and successful Probe binding.
These mutate only metadata of the actual product's unchanged store table.

`tests/support/host_boundaries.rs` preserves READY failure text, exactly one READY,
exactly one cleanup CLOSE forwarding to the actual store CLOSE, successful CLOSE
and exactly three first crossings. The actual Connector/TCP carrier and real MySQL
door also retain declared-need open, undeclared need 1/u32::MAX exact refusal;
owner write; foreign write/read/close exact NotOwner; subsequent owner write and
close success. A bounded wait handles the actual carrier's Pending writes.
Declared transports equal declares.json; BUSBAR_EXPECT_RELEASE still refuses a
debug build. No artificial transport/store implementation supplies these successes.

## Existing backend/auth coverage

All existing logic tests and local Store/plane assertion functions remain.
`tests/harness.rs`, common helpers and e2e use the actual connector/TCP carrier.
Reference URL tests call the actual contract's resolve_declared_fields directly.

Every named test in `mysqlwire_auth_tests.rs` remains, including literal/lent DSN
privacy, native/fast SHA2 bytes, partial writes and Pending, auth switches and
operator flags, sealed cleartext socket full auth, cancel/failure close/reopen
sequence, public-key pins/ciphertext and sequence, secure observed facts, malformed
keys, and empty-password packets. Five narrow raw host callbacks supply only those
scripted auth inputs. The single Handshake owner lends typed OPEN/CANCEL/CLOSE
frames to the actual product door and owns all loans through cleanup; it is not
a generic ABI builder/host/reply framework. The existing mysqlwire sealed-TCP
helper now has one direct WRITE callback with the same actual socket. Production
retains forbid(unsafe_code); test builds alone permit these documented raw ABI
inputs via cfg_attr(not(test), forbid(unsafe_code)). No test-support feature is
added to the contract and no pin is changed.

## Retired framework-only/no-op tests

- Moved-count comparator and doubled-count selfchecks: the deleted Recorder/Fold
  comparator no longer exists; ordinary exact assert_eq! checks cover real calls.
  BUSBAR_CONFORMANCE_RED=count is consequently not a replacement test interface.
- Declared-class-without-case reporting, outbound byte-off/no-field/double-token
  fault injectors: framework selfchecks, and store dispatch never invoked the
  exporter/auth-specific branches for this product.
- Transport FramePiece and plane-answer layout checks: no-op for kind Store.
- Configured credential canary scan: inputs have no `credentials`, so former test
  returned without a MySQL assertion; DSN secrecy assertions remain in auth tests.
- Generated conformance_host generic TLS/framed/guard-mode selfchecks: host framework
  tests, not MySQL behavior. Real Connector/TCP is used for MySQL's actual network
  tests; no copied TLS or host framework is introduced.

## Qualification and remaining integration work

Source formatting and git diff whitespace review pass. **No cargo build, test,
clippy, service run, dropped-library execution or dependency resolution was run**:
the build resource lane has not been approved. This is source migration, not proof
that either ABI or live database run passes. MySQL service/root-password constraints
remain strict; the new full-script/schema/READY tests never skip absent services.
Only the preexisting separate live transcript retains its established local
optional-service/CI-strict gate.

BUSBAR_PLUGIN_CDYLIB names an absolute actual freshly built MySQL cdylib in CI;
missing/stale files fail. Direct developer cargo tests use the deterministic deps
artifact beside their binary. No hashed-artifact search or linked substitute exists.
The canonical reusable CI/renderer must export that path, remove retired comparator
RED controls, and update its macOS live-test filter for the new strict service test
names. Those rendered policy/pin files are outside this authored-test change.
Cargo.lock intentionally remains unchanged as instructed; its now-unreachable kit
records require the separately coordinated resolution step. Final SDK compilation
and both-door service qualification remain outstanding.

## Private monday-audit composition

This private normal merge preserves both ancestry tips: ordinary-test source
`3d39205746dfea510a9b7772e66cc6c1e39125df` and exact read-only-fetched audit donor
`63e8ad1b62436907f6f2399e426afdcddae84a93` (27 audit commits). No public refs,
foreign checkout, SDK/peer pin, policy/publication setting or lock was changed.
KICKOFF STRICT and MERGE-PROMPT-2 were read; root instructions explicitly limit
this work to private source composition, without pushes or local builds.

Conflict mapping:

- README retains the accepted full-u64 raw-usage contract and signed metering
  contract; its existing unsigned-token paragraph already expresses the audit's
  intended correction. No signed-cap behavior is reinstated for raw usage.
- lib.rs retains all production audit fixes: reserved empty usage model refusal
  at both public write boundaries (also at the newer transaction-owned replacement
  helper), truthful key write timestamps, both DROP CHECK/fallback errors, stable
  duplicate operation/constraint names, and refusal plus failed-ROLLBACK text.
  The audit's explicit ApplyError refusal state is also wired into the newer
  correction error path and sequence-error construction.
- mysqlwire.rs retains server packet-ceiling validation, 4096-column refusal,
  broken-connection marking on malformed replies, bare IPv6 host parsing, shared
  duplicate error code and all audit regression tests. The newer sealed CredUrl
  password check supersedes the donor's pre-sealed URL helper; the donor's exact
  TLS-tail privacy/no-password-key-name regression remains intact.
- slots.rs retains newer record_put locking/empty-delete, ledger correction and
  conditional-record implementations, while applying the audit's database-clock
  authority to the shared dedupe sweep and **all three** dedupe insertion paths
  (base writes, corrections and conditional records). It also retains deterministic
  1366/refused-write classification and the shared duplicate constant. No local
  process clock remains in a store_ops stamp or retention cutoff.
- tests.rs keeps both appended test tails: all accepted usage-cleanup transaction,
  writer synchronization, raw-era, attribution and database-token-clock proofs;
  all donor key timestamp, empty model, rollback-reason and billable-refund
  assertions. The existing exact database-clock token boundary witness remains;
  the donor's private-kind replay assertions are retained as the separate
  `a_private_token_kind_preserves_a_replay_at_the_callers_expiry_boundary` test,
  accurately described as a caller-time replay witness. The strengthened current
  tombstone delta/full-hydration test retains the donor's end-state assertions
  and points to the separate atomic-visibility test.
- harness.rs keeps the actual Connector/TCP host and incorporates the donor's odd
  op-id mint/cadence regression. slots_tests.rs keeps accepted full-u64 usage
  behavior and all donor additions: metering crossing from just below i64::MAX,
  exact schema isolation, frozen v9 usage/append/metering bodies and all v10 dedupe
  row checks, plus the skewed server-clock stamp/sweep regression.

The known private TCP module path is corrected to the pinned peer's public
`busbar_transport_tcp::linked::door`. This source has no listener.accept call;
its existing owner I/O retries are bounded at five seconds. The test-only unsafe
cfg carve is unchanged and remains under the explicit root HOLD; production still
forbids unsafe code.

Source inventory found every one of the 246 ordinary-candidate named Rust tests
still present. Donor baseline names `tombstone_and_credential_destruction_share_one_transaction`
and `usage_counters_pin_at_i64_max` map to the already accepted stronger hydration
and full-u64 usage tests; the audit's changed assertions in those areas remain.
No kit imports, conformance macros or authored kit manifest dependencies were
introduced. Old unreachable Cargo.lock kit entries remain for coordinated lock
resolution. Formatting/whitespace review passes; this composition has **not** been
compiled, tested, measured or run against MySQL or a dropped image.


## Root-classified filesystem self-check retirement

Under KICKOFF STRICT 2/3 and the root structural directive, retire only
`the_freshness_gate_ignores_cfg_test_sources`. This test created a synthetic
source directory and modified its file timestamps to judge the test locator's
own filesystem heuristic; it did not exercise MySQL or a product ABI assertion.
Its temporary-file/timestamp construction closures disappear with that test.
`common::newest_source_mtime_under` remains used by the actual artifact locator,
so it is not unused self-check support and is retained unchanged.

The actual explicit BUSBAR_PLUGIN_CDYLIB binding, absolute-path check, missing
artifact hard failure, deterministic developer path and current locator checks
remain unchanged. Every product test, source SQL body and assertion remains;
the backend-free conformance selection now contains eight tests instead of
nine with the same all-minus-live command. The root-approved exact thirteen
item unsafe allowances and default test deny/production forbid are unchanged.
This is source-only retirement with formatting and whitespace checks; no Cargo
or native qualification is performed here.


## Platform connection-refusal oracle

The native Linux `w4_a_connect_failure_is_one_prefix_then_the_driver_words`
receipt returned the complete underlying OS text `Connection refused (os error
111)`, whereas the fixture expected the unrelated phrase `connection was
refused`. The test now independently connects to the same closed local endpoint,
requires `ErrorKind::ConnectionRefused`, and requires the actual store's driver
message to contain the complete observed OS error and exact address. Its exact
single store-prefix count, `Could not connect` text and password non-disclosure
assertions remain. No production error formatting or database behavior changes;
this source follow-up has not been built or run here.


The Statement-identity refusal fixture now changes one same-width ASCII byte of
the actual decoded product name (`busbar-store-mysql`) and proves the changed
rendering still parses with a different name. Appending a trailing zero, as the
prior fixture did, fails the pinned rendering parser's exact-end check before
the loader can compare the actual image's Statement. The test now requires exact
`LoadError::StatementMismatch` and retains its `repack the plugin` diagnostic
assertion. This repairs the input to reach the intended negative product boundary;
it does not accept malformed rendering as a substitute identity proof.


## Root resolution of the empty-model contract conflict

Root resolved this against the existing API/data-format contract: ModelTokens
model identities are strings without an empty-name restriction; correction
validation requires ordered identities and nonzero unit counters, not nonempty
names. Accepted source 3c6bf35c7f87db7665116a457c2b2494af7fc5e5 already
implements independent token and window-counter fields in the same physical
empty-name row, plus unit-table recovery and zero-token sentinel discrimination.
This is a contract resolution, not an oracle exception.

Remove only the contradictory audit `refuse_reserved_model` helper, its three
call sites and `an_empty_usage_model_name_is_refused_by_name` test. Restore the
exact 3f0d27a correction fixture file, including
`empty_model_identity_shares_sentinel_without_losing_requests_tokens_or_open_units`:
ordinary empty-name put/add, full unsigned correction/refund, exact durable
receipt replay, reopen, clear with no phantom empty model, and open-unit-only
empty identity must succeed unchanged. Existing field/counter assertions remain.
All unrelated audit fixes and SQL, the thirteen approved unsafe item allowances,
locks, manifests and pins are unchanged.

The normal e306e7d commit remains in history as the held, non-equivalent proposal;
its valid-name substitution and ledger claim of full preservation are withdrawn.
Its ledger policy section is replaced by this explicit resolution. The primary
conflict packet outside the source clone remains historical evidence, with root
ruling/successor recorded in a separate receipt. This source successor has only
formatting/whitespace review here; independent source review and actual native
qualification are separate requirements.


## Exact operator archive pins in both real-root activation paths

The file-drop fixture now hashes the exact retained newly packed signed MySQL
archive (also asserting it equals the packed bytes), and names that SHA256 in
the generated operator BASE `plugins.fetch` entry before bootstrap. The admin
fixture asserts its retained archive equals the exact uploaded signed bytes,
hashes those retained bytes, and adds that exact pin to the restart BASE before
boot #2 activates the installed store. This matches the existing pinned-core
operator provenance requirement and the PostgreSQL fixture resolution.

No loader/security policy, product source, signature/trust setting, pin or lock
changes. Existing archive/catalog/authentication/bootstrap/durable-MySQL
assertions remain; actual freshly built archive bytes are the pin source.
Formatting/whitespace review only here; native qualification is separate.


The final slot-policy census found the second incompatible audit assertion,
`slots_tests::an_empty_model_name_is_refused_not_failed`. Preserve its distinct
actual ABI/op_id coverage as
`an_empty_model_identity_keeps_independent_counters_and_replays_once`: the same
empty-name additive input succeeds, full get_usage equals independent request,
billable and token fields, raw SQL verifies independent window counters and exact stored unit value, the write has exactly one durable receipt, and its exact replay
changes neither counters nor tokens. The neighboring overlong-value refusal and
all other slot assertions remain unchanged. Bounded source search finds no
remaining empty-model refusal helper/reason/policy assertion. This follows the
root API contract resolution; it does not alter product SQL or runtime policy.
Source formatting/whitespace review only; no author builds/native runs.


The slot fixture's original unit spelling is `tokens_input`, while the pinned
contract's reserved UNIT_INPUT spelling is `input` (records.rs444). Therefore
split_units correctly treats `tokens_input` as an open unit: add_usage_on stores
its count in usage_window_units, while the sentinel's legacy tokens_input column
remains zero. The raw physical oracle is now exact `(requests,billable_requests,
tokens_input) = (1,1,0)` plus `usage_window_units` empty model / exact unit
`tokens_input` count 5 before and after receipt replay. The original ABI input,
full ledger equality, counters, one receipt and replay assertions are unchanged.
The earlier guessed token-column placement was a fixture error; no payload or
production policy changed. Source-only formatting/whitespace review here.
