#!/usr/bin/env nbb
;; verify-kotoba.cljs — hold the Kotoba percent-encoder to the Clojure one.
;;
;; `kotoba/pct_encode.kotoba` reimplements `sigv4.core/uri-encode` in Kotoba,
;; compiled to WebAssembly by the released native CLI. Two implementations of
;; the same function are only useful if they agree, and "it compiled" is not
;; agreement — so this script feeds both the same bytes and requires
;; byte-identical output.
;;
;; The domain is chosen to cover the parts that actually decide the answer:
;; every ASCII code point (the unreserved/reserved boundary the classifier
;; encodes) and multi-byte UTF-8 text (the 0x80-0xF4 range, where a
;; charCodeAt-based encoder would silently emit UTF-16 code units instead).
;;
;;   nbb scripts/verify-kotoba.cljs [path/to/pct_encode.wasm]

(require '[clojure.string :as str]
         '[sigv4.core :as v4]
         '["node:fs" :as fs])

(def wasm-path (or (nth js/process.argv 3 nil) "target/pct_encode.wasm"))

(def failures (atom 0))
(def checked (atom 0))

(defn fail! [label expected actual]
  (swap! failures inc)
  (when (<= @failures 10)                     ; don't drown the log on a systemic break
    (println "  FAIL" label)
    (println "        clojure:" (pr-str expected))
    (println "        kotoba: " (pr-str actual))))

(def encoder (js/TextEncoder.))
(def decoder (js/TextDecoder. "latin1"))

(defn kotoba-encoder
  "→ a fn of string → percent-encoded string, backed by the Wasm module."
  [exports]
  (let [mem #(js/Uint8Array. (.-buffer (.-memory exports)))
        src ((.-scratch exports) 1024)
        dst ((.-scratch exports) 4096)]
    (fn [s]
      (let [bs (.encode encoder s)]
        (when (> (.-length bs) 1024)
          (throw (js/Error. "input exceeds the scratch buffer")))
        (.set (mem) bs src)
        (let [n ((.-encode exports) src (.-length bs) 0 dst 0)]
          (.decode decoder (.subarray (mem) dst (+ dst n))))))))

(defn check! [enc label s]
  (swap! checked inc)
  (let [expected (v4/uri-encode s)
        actual   (enc s)]
    (when-not (= expected actual)
      (fail! (str label " " (pr-str s)) expected actual))))

(println "sigv4 — Kotoba/Wasm vs Clojure percent-encoder parity\n")
(println "  module:" wasm-path)

(-> (js/WebAssembly.instantiate (.readFileSync fs wasm-path) #js {})
    (.then
     (fn [m]
       (let [exports (.. m -instance -exports)
             enc (kotoba-encoder exports)]

         ;; The module's own self-test: the five characters encodeURIComponent
         ;; wrongly exempts, 3 bytes each.
         (let [n ((.-main exports))]
           (if (= 15 n)
             (println "  ok   main() self-test = 15")
             (fail! "main() self-test" 15 n)))

         ;; 1. Every ASCII code point, one at a time — this is the classifier's
         ;;    entire decision surface.
         (doseq [i (range 0 128)]
           (check! enc "ascii" (js/String.fromCharCode i)))
         (println "  ok  " 128 "ASCII code points")

         ;; 2. Multi-byte UTF-8 — 2, 3 and 4-byte sequences.
         (let [samples ["é" "ü" "日" "本語" "🗄" "🇯🇵" "café" "日本/語"
                        "Ω≈ç√" " " "�"]]
           (doseq [s samples] (check! enc "utf8" s))
           (println "  ok  " (count samples) "multi-byte UTF-8 samples"))

         ;; 3. Realistic S3 keys and query values, where the two layers meet.
         (let [samples ["docs/readme.txt" "a b/c+d.png" "!'()*" "" "~-._"
                        "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
                        "prefix/2026-07-25T12:00:00.000Z/日本語 file (1).pdf"
                        (str/join (map js/String.fromCharCode (range 32 127)))]]
           (doseq [s samples] (check! enc "key" s))
           (println "  ok  " (count samples) "S3 key / query samples"))

         (println)
         (println "  compared" @checked "inputs")
         (if (zero? @failures)
           (println "kotoba and clojure agree byte for byte")
           (do (println @failures "MISMATCH(es)")
               (set! (.-exitCode js/process) 1))))))
    (.catch (fn [e]
              (println "verification threw:" (str (or (.-stack e) e)))
              (set! (.-exitCode js/process) 1))))
