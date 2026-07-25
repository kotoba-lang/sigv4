# sigv4

`sigv4.*` — AWS Signature Version 4, **signing and verification**, as portable
`.cljc` with injected crypto. The shared implementation for every S3-compatible
surface in this workspace.

| Namespace | What it owns |
|---|---|
| `sigv4.core` | The pure half — encoding, canonicalization, credential scope, string-to-sign, presign params. No crypto, no clock, no I/O. |
| `sigv4.verify` | The server side — parse `Authorization`, recompute the expected signature, compare in constant time. |
| `sigv4.crypto` | Optional default `ICrypto` (`javax.crypto` / WebCrypto). |
| `sigv4.protocols` | The one host seam: `ICrypto`. |
| `kotoba/pct_encode.kotoba` | The percent-encoder, again — in Kotoba, compiled to Wasm, held byte-equal to `sigv4.core`. |

## Why this exists

SigV4 was implemented **eight times** across this workspace before this library:

| Copy | |
|---|---|
| `gftdcojp/net-kotobase` `kotobase.sigv4` | the original |
| `gftdcojp/net-kotobase-ipfs` `kotobase-ipfs.sigv4` | documented verbatim copy of it |
| `kotoba-lang/kotobase-peer` `object-store.s3-sigv4` | |
| `kotoba-lang/kotobase-peer-atomic` | byte-identical to the above |
| `kotoba-lang/kotobase-peer-main-test` | byte-identical to the above |
| `kotoba-lang/kotobase-protocols-worker` `sigv4` | the verification side |
| `kotoba-lang/kotobase-protocols` `protocols.s3` | |
| `kotoba-lang/io-storj` | now depends on this library instead |

Each was a locally correct decision — `net-kotobase-ipfs` copied rather than
depended precisely to stay single-purpose and low-privilege. The cost only
shows up in aggregate: **the copies had already diverged.** The verification
side percent-encodes with `charCodeAt`, so it emits UTF-16 code units and signs
any non-ASCII key or query value differently from AWS and from every S3 SDK —
a defect the signing copies do not share. Eight implementations means eight
places for that to be true and one place where anyone would notice.

## Usage

```clojure
(require '[sigv4.core :as v4]
         '[sigv4.crypto :as crypto]
         '[sigv4.protocols :as p])

(def c (crypto/crypto))

;; sign
(let [{:keys [canonical-request signed-headers]}
      (v4/canonical-request {:method :get
                             :path (v4/object-path "my-bucket" "docs/a.txt")
                             :query ""
                             :headers {"host" "gateway.storjshare.io"
                                       "x-amz-content-sha256" v4/empty-payload-sha256
                                       "x-amz-date" "20260725T120000Z"}
                             :payload-hash v4/empty-payload-sha256})
      scope (v4/credential-scope "20260725" "us-east-1")]
  (v4/string-to-sign "20260725T120000Z" scope (p/-sha256-hex c canonical-request)))

;; verify
(require '[sigv4.verify :as verify])
(let [parsed (verify/parse-authorization (get-in req [:headers "authorization"]))
      expected (verify/expected-signature c {:secret-key secret
                                             :parsed parsed
                                             :amz-date amz-date
                                             :payload-hash body-hash
                                             :request req})]
  (verify/constant-time-eq? (:signature parsed) expected))
```

Signing an S3 object store end to end — client, endpoint validation, presigned
URLs — is [`kotoba-lang/io-storj`](https://github.com/kotoba-lang/io-storj),
which builds on this.

## Design

**No clock, no crypto, no I/O in `sigv4.core`.** Every signing entry point takes
the timestamp as an ISO-8601 string, and SHA-256/HMAC arrive through `ICrypto`.
That is what makes the reference vectors reproducible, and it keeps the
namespace identical on every runtime in the kotoba-lang ladder.

**`signing-key-chain` returns the HMAC inputs, not a key.** The host folds its
own HMAC over them, so this library derives signing keys without ever touching
a cipher.

**One code path for sync and async.** `javax.crypto` returns bytes;
`crypto.subtle` returns Promises of bytes. Consumers compose through a `then`
that is plain application on the JVM and `.then` on JS. On the JVM these
functions return values; on ClojureScript, Promises of the same values.

**No transport protocol.** A signer produces a signed request; putting it on the
wire belongs to whoever owns the connection — and every consumer already has one.

### Why no AWS SDK

An S3 SDK would make this JVM-only or Node-only, which forfeits the runtimes
that consume it: Cloudflare Workers, browser peers, nbb scripts, the JVM. SigV4
is string manipulation plus SHA-256 and HMAC-SHA-256, and every target runtime
already has both.

## Correctness

SigV4 fails silently: a wrong byte anywhere produces a valid-looking request and
an opaque `403 SignatureDoesNotMatch`. So the tests do not assert our own output
back to us.

- **AWS reference vectors.** The canonical request, string-to-sign and
  **signature** AWS documents for its two worked S3 examples — header auth
  (`f0e8bdb8…`) and query-string auth (`aeeed9bb…`).
- **Signing closed against verification.** `verify_test` signs AWS's example and
  then verifies it. A drift between the two halves fails there rather than in
  production as an unexplained 403.
- **Two-runtime parity.** `nbb scripts/verify-cljs.cljs` re-runs the
  load-bearing assertions on WebCrypto, where the async path through `then` is
  genuinely different code. Most consumers of this library run in Workers.
- **Kotoba/Wasm parity.** `nbb scripts/verify-kotoba.cljs` requires the Kotoba
  implementation and the Clojure one to agree byte for byte across 147 inputs.

All four run in CI.

```bash
clojure -M:test                 # JVM
nbb scripts/verify-cljs.cljs    # ClojureScript / WebCrypto
nbb scripts/verify-kotoba.cljs  # Kotoba/Wasm vs Clojure  (needs target/pct_encode.wasm)
clojure -M:lint
```

## The Kotoba implementation

`kotoba/pct_encode.kotoba` is a second, independent implementation of
`sigv4.core/uri-encode`, written in Kotoba and compiled by the released native
CLI to a ~500-byte Wasm module.

Percent-encoding is the right slice to own in Kotoba: it is the single most
failure-prone step in SigV4 (S3 does not exempt the characters
`encodeURIComponent` exempts, and demands uppercase hex), and it is pure
byte-to-byte work — no maps, no sorting, no host capability. It runs on `alloc`,
`mem-byte-at` and `byte-store!` over the module's linear memory, with
self-recursion in place of a loop form.

```bash
kotoba wasm emit kotoba/pct_encode.kotoba --package-lock kotoba.lock.edn \
  --output target/pct_encode.wasm --json
nbb scripts/verify-kotoba.cljs
```

**What is not in Kotoba, and why.** The rest of SigV4 — sorting headers,
canonical query assembly, string-to-sign — needs maps, string collections and a
sort. Those are not in the Wasm subset today, so the composition layer stays
`.cljc`. Two further limits are worth recording because they shaped this module:

- The Wasm emitter rejects `:require` across modules (`internal-error` on
  v0.6.29), so the classifier is inlined rather than split into its own module.
- The `web`/ESM target, which *does* support multi-module, has no admitted
  lowering for `alloc` / `mem-byte-at` / `byte-store!` (`operation has no
  admitted lowering`), so this cannot be an ESM pilot the way `io-ipfs`'s is.

This is a real slice, not a relabelling: it is compiled from `.kotoba` by the
checksum-verified released CLI and held to byte-equality with the Clojure
implementation. It is not yet load-bearing — `sigv4.core/uri-encode` is what
consumers call. Promoting it is a decision for when the composition layer can
follow it.

## License

Apache-2.0.
