#-*- coding: utf-8 -*-  
from __future__ import absolute_import, division, print_function

from nacl._lib import lib
from nacl.exceptions import CryptoError

crypto_scalarmult_BYTES = lib.crypto_generichash_bytes()

def crypto_generichash(in_, key):

	if not key :
		key = lib.ffi.NULL
		key_len = 0
	else:
		key_len = len(key)

	out = lib.ffi.new("unsigned char *", crypto_scalarmult_BYTES)
	out_len = crypto_scalarmult_BYTES

	ret = lib.crypto_generichash(out, out_len, in_, len(in_), key, key_len)
	print ("ret: %d" % ret)
	if lib.crypto_generichash(out, out_len, in_, len(in_), key, key_len) != 0:
		raise CryptoError("An error occurred while crypto_generichash")

	return lib.ffi.buffer(out, out_len)[:]
