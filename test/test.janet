(import testament :prefix "" :exit true)
(use ../simple-janet-crypto)

(def plaintext "some text")

(deftest encrypt
  (def k (generate-encryption-key))
  (def ciphertext (encrypt k "" plaintext))
  (def decrypted (decrypt k "" ciphertext))
  (is (= plaintext (string decrypted))))

(deftest sign
  (def k (generate-hmac-key))
  (def signature (sign k plaintext))
  (is (verify k plaintext signature)))

(deftest password
  (def k (generate-derivation-key))
  (def pepper (derive-pepper k "test"))
  (is (= pepper (derive-pepper k "test")))
  (def digested (password plaintext pepper))
  (is (password-verify plaintext pepper digested)))

(run-tests!)