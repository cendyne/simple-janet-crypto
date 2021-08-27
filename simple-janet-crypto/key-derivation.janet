# Copyright (c) 2021 Cendyne
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
(use janetls)

(defn generate [bytes] (util/random bytes))

(defn derive-context [key ad &opt len]
  (unless key "key is missing")
  (unless ad "additional data (ad) is missing")
  (default len 8)
  # There is no salt
  (kdf/hkdf :sha256 key len ad ""))

(def- key-size/sha256 32)
(def- key-size/chacha20 32)

(defn generate-encryption-key [] (generate key-size/chacha20))
(defn generate-hmac-key [] (generate key-size/sha256))
(defn generate-derivation-key [] (generate key-size/sha256))

(defn generate-salt [&opt bytes]
  (default bytes 12)
  (generate bytes))

(defn derive-pepper [key ad]
  # NIST: 14 bytes pepper minimum
  (derive-context key ad 14))

(defn derive-hmac-key [key context salt &opt len]
  (unless key (error "key is missing"))
  (unless context (error "context is missing"))
  (unless salt (error "salt is missing"))
  (default len 32)
  (kdf/hkdf :sha256 key len context salt))
