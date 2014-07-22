# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function

from nacl._lib import lib
from nacl.exceptions import CryptoError

crypto_shorthash_KEYBYTES = lib.crypto_shorthash_keybytes()
crypto_shorthash_BYTES = lib.crypto_shorthash_bytes()

def crypto_shorthash(in_, k):

	if not in_ :
		in_ = lib.ffi.new("unsigned char []", 1)
		in_len = 0
	else:
		in_len = len(in_)

	out = lib.ffi.new("unsigned char []", crypto_shorthash_BYTES)

	if lib.crypto_shorthash(out, in_, in_len, k) != 0:
		raise CryptoError("An error occurred while crypto_shorthash")

	return lib.ffi.buffer(out, crypto_shorthash_BYTES)[:]
