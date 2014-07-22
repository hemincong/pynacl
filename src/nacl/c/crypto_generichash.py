#-*- coding: utf-8 -*-  
from __future__ import absolute_import, division, print_function

from nacl._lib import lib
from nacl.exceptions import CryptoError

crypto_generichash_BYTES = lib.crypto_generichash_bytes()
crypto_generichash_BYTES_MIN = lib.crypto_generichash_bytes_min()
crypto_generichash_BYTES_MAX = lib.crypto_generichash_bytes_max()
crypto_generichash_KEYBYTES = lib.crypto_generichash_keybytes()
crypto_generichash_KEYBYTES_MIN = lib.crypto_generichash_keybytes_min()
crypto_generichash_KEYBYTES_MAX = lib.crypto_generichash_keybytes_max()

def crypto_generichash(message, key, out_len=crypto_generichash_BYTES):
	#if out_len < crypto_generichash_BYTES_MIN:
		#raise CryptoError("out_len length shorter than crypto_generichash_BYTES_MIN")
	if out_len > crypto_generichash_BYTES_MAX:
		raise CryptoError("out_len length longer than crypto_generichash_BYTES_MAX")

	if not isinstance(message, (str)):
		raise CryptoError("message must be str")

	message_len = len(message)

	if not key:
		key = lib.ffi.NULL
		key_len = 0
	else:
		key_len = len(key)
		if key_len < crypto_generichash_KEYBYTES_MIN:
			raise CryptoError("key length shorter than crypto_generichash_keybytes_min")
		if key_len > crypto_generichash_KEYBYTES_MAX:
			raise CryptoError("key length longer than crypto_generichash_keybytes_max")

	out = lib.ffi.new("unsigned char[]", out_len)

	if lib.crypto_generichash(out, out_len, message, message_len, key, key_len) != 0:
		raise CryptoError("An error occurred while crypto_generichash")

	return lib.ffi.buffer(out, out_len)[:]
