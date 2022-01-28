(ns daaku.ulid-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest testing is]])
  (:import [daaku.ulid ULID]))

(def max-time (long 0x0000ffffffffffff))
(def zero-entropy (byte-array 10 (byte 0)))
(def filled-entropy (byte-array 10 (byte -1)))

(defn- entropy [& bytes]
  (byte-array (map byte bytes)))

(deftest shebang
  (run! (fn [[ts entropy ulid]]
          (testing "isValid"
            (is (ULID/isValid ulid))
            (is (ULID/isValid (str/upper-case ulid))))
          (testing "encode"
            (is (= ulid (ULID/encode ts entropy))))
          (testing "timestamp"
            (is (= ts (ULID/timestamp ulid)))
            (is (= ts (ULID/timestamp (str/upper-case ulid))))))
        [[0 zero-entropy "00000000000000000000000000"]
         [0 filled-entropy "0000000000zzzzzzzzzzzzzzzz"]
         [max-time zero-entropy "7zzzzzzzzz0000000000000000"]
         [0x00000001 zero-entropy "00000000010000000000000000"]
         [0x0000000f zero-entropy "000000000f0000000000000000"]
         [0x00000010 zero-entropy "000000000g0000000000000000"]
         [0x00000011 zero-entropy "000000000h0000000000000000"]
         [0x0000001f zero-entropy "000000000z0000000000000000"]
         [0x00000020 zero-entropy "00000000100000000000000000"]
         [0x00000021 zero-entropy "00000000110000000000000000"]
         [0x0000002f zero-entropy "000000001f0000000000000000"]
         [0x00000030 zero-entropy "000000001g0000000000000000"]
         [0x00000031 zero-entropy "000000001h0000000000000000"]
         [0x0000003f zero-entropy "000000001z0000000000000000"]
         [0x00000040 zero-entropy "00000000200000000000000000"]
         [0x000000f0 zero-entropy "000000007g0000000000000000"]
         [0x000000ff zero-entropy "000000007z0000000000000000"]
         [0x00000100 zero-entropy "00000000800000000000000000"]
         [0x00000101 zero-entropy "00000000810000000000000000"]
         [0x000001ff zero-entropy "00000000fz0000000000000000"]
         [0x00000200 zero-entropy "00000000g00000000000000000"]
         [0x00000201 zero-entropy "00000000g10000000000000000"]
         [0x000002ff zero-entropy "00000000qz0000000000000000"]
         [0x00000300 zero-entropy "00000000r00000000000000000"]
         [0x00000301 zero-entropy "00000000r10000000000000000"]
         [0x000003ff zero-entropy "00000000zz0000000000000000"]
         [0x00000400 zero-entropy "00000001000000000000000000"]
         [0x00000401 zero-entropy "00000001010000000000000000"]
         [0x000007ff zero-entropy "00000001zz0000000000000000"]
         [0x00000800 zero-entropy "00000002000000000000000000"]
         [0x00007fff zero-entropy "0000000zzz0000000000000000"]
         [0 (entropy 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x01)
          "00000000000000000000000001"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0f)
          "0000000000000000000000000f"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x10)
          "0000000000000000000000000g"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x1f)
          "0000000000000000000000000z"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x20)
          "00000000000000000000000010"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x21)
          "00000000000000000000000011"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x2f)
          "0000000000000000000000001f"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x30)
          "0000000000000000000000001g"]
         [0 (entropy  0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x3f)
          "0000000000000000000000001z"]]))

(deftest invalid-ulids
  (run! #(is (not (ULID/isValid %)))
        [nil
         ""
         "0"
         "000000000000000000000000000"
         "-0000000000000000000000000"
         "0000000000000000000000000U"
         "0000000000000000000000000/u3042"
         "0000000000000000000000000#"]))

(deftest gen
  (let [ulid (ULID/gen)]
    (is (= 26 (count ulid)))
    (is (ULID/isValid ulid))))
