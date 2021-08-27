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

(def- cipher :chacha20-poly1305)

(defn- split-secret [secret]
  (def len (length secret))
  (def nonce (byteslice secret 0 12))
  (def tag-position (- len 16))
  (def tag (byteslice secret tag-position))
  (def ciphertext-len (- len 12 16))
  (def ciphertext (byteslice secret 12 ciphertext-len))
  [nonce ciphertext tag])

(defn encrypt [key ad plaintext]
  (unless (bytes? plaintext)
    (error "plaintext is missing or is not a string like thing"))
  (as-> plaintext ?
    (string (splice (cipher/encrypt cipher key nil ad ?)))
    (encoding/encode ? :base64 :url-unpadded)
    ))

(defn decrypt [key ad secret]
  (def secret (if secret (encoding/decode secret :base64 :url-unpadded)))
  (if (and secret (> (length secret) (+ 16 12))) (do
    (def [iv ciphertext tag] (split-secret secret))
    (cipher/decrypt cipher key iv ad ciphertext tag)
  )))
