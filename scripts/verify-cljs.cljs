#!/usr/bin/env nbb
;; verify-cljs.cljs — two-runtime parity check.
;;
;; `clojure -M:test` proves the library on the JVM, where crypto is synchronous
;; and every `then` is plain application. That leaves the half that actually
;; ships to browsers and Cloudflare Workers untested: WebCrypto is Promise-based,
;; so the *same* source takes a completely different path. A green JVM suite
;; says nothing about it — and Workers are where most consumers of this library
;; run.
;;
;; So this re-runs the load-bearing assertions — AWS's two published reference
;; signatures, and the sign/verify agreement — through nbb on crypto.subtle.
;; Identical expected values, different runtime.
;;
;;   nbb scripts/verify-cljs.cljs

(require '[sigv4.core :as v4]
         '[sigv4.crypto :as crypto]
         '[sigv4.protocols :as p]
         '[sigv4.verify :as verify])

(def failures (atom 0))

(defn check [label expected actual]
  (if (= expected actual)
    (println "  ok  " label)
    (do (swap! failures inc)
        (println "  FAIL" label)
        (println "        expected:" (pr-str expected))
        (println "        actual:  " (pr-str actual)))))

(def c (crypto/crypto))
(def aws-secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

(defn signing-key
  "Fold the HMAC ladder over Promises — the async mirror of the JVM reduce."
  [secret short region]
  (let [{:keys [seed steps]} (v4/signing-key-chain secret short region)]
    (reduce (fn [p step] (.then p #(p/-hmac c % step)))
            (js/Promise.resolve seed)
            steps)))

(defn sign-string [secret short region sts]
  (-> (signing-key secret short region)
      (.then #(p/-hmac c % sts))
      (.then #(p/-hex c %))))

;; ── 1. WebCrypto digests agree with the JVM's ────────────────────────────────
(defn check-digests []
  (js/Promise.all
   #js [(.then (p/-sha256-hex c "") #(check "sha256 of empty string" v4/empty-payload-sha256 %))
        (.then (p/-sha256-hex c "hello")
               #(check "sha256 of \"hello\""
                       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" %))
        (.then (p/-sha256-hex c "日本語")
               #(check "sha256 is UTF-8, not UTF-16"
                       "77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5" %))]))

;; ── 2. AWS's published header-auth signature ─────────────────────────────────
(def aws-canonical
  (str "GET\n/test.txt\n\n"
       "host:examplebucket.s3.amazonaws.com\n"
       "range:bytes=0-9\n"
       "x-amz-content-sha256:" v4/empty-payload-sha256 "\n"
       "x-amz-date:20130524T000000Z\n\n"
       "host;range;x-amz-content-sha256;x-amz-date\n"
       v4/empty-payload-sha256))

(defn check-aws-header-vector []
  (-> (p/-sha256-hex c aws-canonical)
      (.then (fn [cr-hash]
               (check "AWS canonical-request hash"
                      "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972" cr-hash)
               (sign-string aws-secret "20130524" "us-east-1"
                            (v4/string-to-sign "20130524T000000Z"
                                               (v4/credential-scope "20130524" "us-east-1")
                                               cr-hash))))
      (.then #(check "AWS documented header-auth signature"
                     "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" %))))

;; ── 3. AWS's published query-string-auth signature ───────────────────────────
(defn check-aws-presign-vector []
  (let [scope (v4/credential-scope "20130524" "us-east-1")
        qs    (v4/canonical-query
               (v4/presign-params {:key-id          "AKIAIOSFODNN7EXAMPLE"
                                   :scope           scope
                                   :long-date       "20130524T000000Z"
                                   :expires-seconds 86400
                                   :signed-headers  "host"}))
        cr    (:canonical-request
               (v4/canonical-request {:method       :get
                                      :path         "/test.txt"
                                      :query        qs
                                      :headers      {"host" "examplebucket.s3.amazonaws.com"}
                                      :payload-hash v4/unsigned-payload}))]
    (-> (p/-sha256-hex c cr)
        (.then #(sign-string aws-secret "20130524" "us-east-1"
                             (v4/string-to-sign "20130524T000000Z" scope %)))
        (.then #(check "AWS documented query-string-auth signature"
                       "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404" %)))))

;; ── 4. Verification, on the async path ───────────────────────────────────────
(def auth
  (str "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
       "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
       "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

(def request
  {:method :get :path "/test.txt" :query nil
   :headers {"host" "examplebucket.s3.amazonaws.com"
             "range" "bytes=0-9"
             "x-amz-content-sha256" v4/empty-payload-sha256
             "x-amz-date" "20130524T000000Z"}})

(defn check-verify []
  (let [parsed (verify/parse-authorization auth)]
    (check "parse-authorization service" "s3" (:service parsed))
    (-> (verify/expected-signature c {:secret-key aws-secret
                                      :parsed parsed
                                      :amz-date "20130524T000000Z"
                                      :payload-hash v4/empty-payload-sha256
                                      :request request})
        (.then (fn [sig]
                 (check "verification reproduces AWS's signature"
                        (:signature parsed) sig)
                 (check "constant-time-eq? accepts it" true
                        (verify/constant-time-eq? (:signature parsed) sig))))
        (.then (fn [_]
                 (verify/expected-signature
                  c {:secret-key aws-secret
                     :parsed parsed
                     :amz-date "20130524T000000Z"
                     :payload-hash v4/empty-payload-sha256
                     :request (assoc-in request [:headers "range"] "bytes=0-999999")})))
        (.then (fn [sig]
                 (check "a tampered Range does not verify" false
                        (verify/constant-time-eq? (:signature parsed) sig)))))))

;; ── 5. Pure layer, unchanged across runtimes ─────────────────────────────────
(defn check-pure []
  (check "uri-encode does not exempt !'()*" "%21%27%28%29%2A" (v4/uri-encode "!'()*"))
  (check "uri-encode emits UTF-8 bytes" "%E6%97%A5" (v4/uri-encode "日"))
  (check "object-path keeps separators" "/b/a%20b/c.txt" (v4/object-path "b" "a b/c.txt"))
  (check "credential-scope carries a non-s3 service"
         "20130524/us-east-1/execute-api/aws4_request"
         (v4/credential-scope "20130524" "us-east-1" "execute-api"))
  (js/Promise.resolve nil))

(println "sigv4 — ClojureScript / WebCrypto parity check (nbb)\n")
(-> (js/Promise.resolve nil)
    (.then check-pure)
    (.then check-digests)
    (.then check-aws-header-vector)
    (.then check-aws-presign-vector)
    (.then check-verify)
    (.then (fn [_]
             (println)
             (if (zero? @failures)
               (println "all checks passed on the ClojureScript path")
               (do (println @failures "check(s) FAILED")
                   (set! (.-exitCode js/process) 1)))))
    (.catch (fn [e]
              (println "verification threw:" (str (or (.-stack e) e)))
              (set! (.-exitCode js/process) 1))))
