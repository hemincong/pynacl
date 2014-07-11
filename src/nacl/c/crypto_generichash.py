#-*- coding: utf-8 -*-  
from __future__ import absolute_import, division, print_function

from nacl._lib import lib
from nacl.exceptions import CryptoError

crypto_generichash_BYTES = lib.crypto_generichash_bytes()

def crypto_generichash(in_, key):

	in_len = len(in_)

	if not key :
		key = lib.ffi.NULL
		key_len = 0
	else:
		key_len = len(key)

	out_len = crypto_generichash_BYTES
	out = lib.ffi.new("unsigned char[]", out_len)

	if lib.crypto_generichash(out, out_len, in_, in_len, key, key_len) != 0:
		raise CryptoError("An error occurred while crypto_generichash")

	return lib.ffi.buffer(out, out_len)[:]
