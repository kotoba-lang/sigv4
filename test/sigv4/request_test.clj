(ns sigv4.request-test
  "The composed signer.

  The expected signatures were produced by an independent implementation
  (Node's `crypto`, driven straight from the SigV4 spec) rather than by this
  library — the same values `kotoba-lang/io-storj` pins, which is what makes
  them a cross-check and not a snapshot.

  JVM-only; the async path is covered by `scripts/verify-cljs.cljs`."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [sigv4.core :as v4]
            [sigv4.crypto :as crypto]
            [sigv4.request :as req]
            [sigv4.verify :as verify]))

(def c (crypto/crypto))
(def now "2026-07-25T12:00:00.000Z")

(def base
  {:endpoint "https://gateway.storjshare.io"
   :bucket "my-bucket"
   :region "us-east-1"
   :access-key "jwtest"
   :secret-key "supersecret"
   :now now})

(defn- signature-of [signed]
  (second (re-find #"Signature=([0-9a-f]+)" (get-in signed [:headers "authorization"]))))

(deftest signed-get-matches-independent-implementation
  (let [s (req/signed c (assoc base :method :get :key "docs/readme.txt"))]
    (is (= "GET" (:method s)))
    (is (= "https://gateway.storjshare.io/my-bucket/docs/readme.txt" (:url s)))
    (is (= "gateway.storjshare.io" (get-in s [:headers "host"])))
    (is (= "20260725T120000Z" (get-in s [:headers "x-amz-date"])))
    (is (= v4/empty-payload-sha256 (get-in s [:headers "x-amz-content-sha256"])))
    (is (str/starts-with?
         (get-in s [:headers "authorization"])
         (str "AWS4-HMAC-SHA256 Credential=jwtest/20260725/us-east-1/s3/aws4_request, "
              "SignedHeaders=host;x-amz-content-sha256;x-amz-date, ")))
    (is (= "2f164e6a8b8805003436d9150ca22b2ed89f4bdcfa505bb0bcfe36d42d2ca528"
           (signature-of s)))))

(deftest signed-put-hashes-the-body-and-signs-extra-headers
  (let [s (req/signed c (assoc base :method :put :key "docs/readme.txt"
                               :body "hello storj"
                               :headers {"Content-Type" "text/plain"}))]
    (is (= "PUT" (:method s)))
    (is (= "hello storj" (:body s)))
    (testing "x-amz-content-sha256 is the digest of the body"
      (is (= "275a8f4e11cbf657431976aba8402192cd60919fede551e0a9bc59ea001a43bf"
             (get-in s [:headers "x-amz-content-sha256"]))))
    (testing "header names are lowercased before signing"
      (is (= "text/plain" (get-in s [:headers "content-type"])))
      (is (str/includes? (get-in s [:headers "authorization"])
                         "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")))
    (is (= "b1433226d0b4bd5f58abdba0d533a353997dca3ab90bf3fdee6aa43c7527cf6b"
           (signature-of s)))))

(deftest presigned-matches-independent-implementation
  (is (= (str "https://gateway.storjshare.io/my-bucket/docs/readme.txt"
              "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
              "&X-Amz-Credential=jwtest%2F20260725%2Fus-east-1%2Fs3%2Faws4_request"
              "&X-Amz-Date=20260725T120000Z"
              "&X-Amz-Expires=3600"
              "&X-Amz-SignedHeaders=host"
              "&X-Amz-Signature=8890b75c4127c944b41ade4dcacb46afd437ab9ce89678bf3d9139c9e1b78fb9")
         (req/presigned c (assoc base :key "docs/readme.txt")))))

(deftest endpoint-trailing-slash-is-normalized
  (is (= (:url (req/signed c (assoc base :method :get :key "a.txt")))
         (:url (req/signed c (assoc base :method :get :key "a.txt"
                                    :endpoint "https://gateway.storjshare.io/"))))))

(deftest query-parameters-are-canonically-ordered
  (let [s (req/signed c (assoc base :method :get :key nil
                               :query {"prefix" "docs/" "list-type" "2"}))]
    (is (= "https://gateway.storjshare.io/my-bucket?list-type=2&prefix=docs%2F" (:url s)))))

(deftest non-s3-services-sign-under-their-own-scope
  (let [s (req/signed c (assoc base :method :get :key "a" :service "execute-api"))]
    (is (str/includes? (get-in s [:headers "authorization"])
                       "Credential=jwtest/20260725/us-east-1/execute-api/aws4_request"))))

(deftest unsigned-payload-is-honoured
  (let [s (req/signed c (assoc base :method :put :key "big.bin"
                               :payload-hash v4/unsigned-payload))]
    (is (= "UNSIGNED-PAYLOAD" (get-in s [:headers "x-amz-content-sha256"])))))

(deftest signing-round-trips-through-verification
  (testing "what this library signs, this library accepts — the property every
            consumer of both halves depends on"
    (doseq [[label key headers]
            [["ascii"     "docs/readme.txt" {}]
             ;; the copies this replaces encoded with encodeURIComponent or
             ;; charCodeAt; both get these wrong in different ways
             ["non-ascii" "docs/日本語 file (1).pdf" {}]
             ["reserved"  "docs/!'()*.txt" {}]
             ["headers"   "a.txt" {"content-type" "text/plain"}]]]
      (let [s (req/signed c (assoc base :method :put :key key
                                   :body "payload" :headers headers))
            parsed (verify/parse-authorization (get-in s [:headers "authorization"]))
            expected (verify/expected-signature
                      c {:secret-key (:secret-key base)
                         :parsed parsed
                         :amz-date (get-in s [:headers "x-amz-date"])
                         :payload-hash (get-in s [:headers "x-amz-content-sha256"])
                         :request {:method :put
                                   :path (v4/object-path (:bucket base) key)
                                   :query nil
                                   :headers (:headers s)}})]
        (is (verify/constant-time-eq? (:signature parsed) expected) label)))))
