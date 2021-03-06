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

from nacl.c.crypto_box import (
    crypto_box, crypto_box_BEFORENMBYTES, crypto_box_BOXZEROBYTES,
    crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES, crypto_box_ZEROBYTES, crypto_box_afternm,
    crypto_box_beforenm, crypto_box_keypair, crypto_box_open,
    crypto_box_open_afternm,
)
from nacl.c.crypto_hash import (
    crypto_hash, crypto_hash_BYTES, crypto_hash_sha256,
    crypto_hash_sha256_BYTES, crypto_hash_sha512, crypto_hash_sha512_BYTES,
)
from nacl.c.crypto_scalarmult import (
    crypto_scalarmult, crypto_scalarmult_BYTES, crypto_scalarmult_SCALARBYTES,
    crypto_scalarmult_base
)
from nacl.c.crypto_secretbox import (
    crypto_secretbox, crypto_secretbox_BOXZEROBYTES, crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES, crypto_secretbox_ZEROBYTES,
    crypto_secretbox_open
)
from nacl.c.crypto_sign import (
    crypto_sign, crypto_sign_BYTES, crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES, crypto_sign_SEEDBYTES, crypto_sign_keypair,
    crypto_sign_open, crypto_sign_seed_keypair,
)
from nacl.c.randombytes import randombytes
from nacl.c.crypto_generichash import crypto_generichash
from nacl.c.crypto_shorthash import (
		crypto_shorthash_KEYBYTES, crypto_shorthash_BYTES, 
		crypto_shorthash,
)
from nacl.c.sodium_core import sodium_init


__all__ = [
    "crypto_box_SECRETKEYBYTES",
    "crypto_box_PUBLICKEYBYTES",
    "crypto_box_NONCEBYTES",
    "crypto_box_ZEROBYTES",
    "crypto_box_BOXZEROBYTES",
    "crypto_box_BEFORENMBYTES",
    "crypto_box_keypair",
    "crypto_box",
    "crypto_box_open",
    "crypto_box_beforenm",
    "crypto_box_afternm",
    "crypto_box_open_afternm",

    "crypto_hash_BYTES",
    "crypto_hash_sha256_BYTES",
    "crypto_hash_sha512_BYTES",
    "crypto_hash",
    "crypto_hash_sha256",
    "crypto_hash_sha512",

    "crypto_scalarmult_BYTES",
    "crypto_scalarmult_SCALARBYTES",
    "crypto_scalarmult",
    "crypto_scalarmult_base",
    "crypto_scalarmult",

    "crypto_secretbox_KEYBYTES",
    "crypto_secretbox_NONCEBYTES",
    "crypto_secretbox_ZEROBYTES",
    "crypto_secretbox_BOXZEROBYTES",
    "crypto_secretbox",
    "crypto_secretbox_open",

    "crypto_sign_BYTES",
    "crypto_sign_SEEDBYTES",
    "crypto_sign_PUBLICKEYBYTES",
    "crypto_sign_SECRETKEYBYTES",
    "crypto_sign_keypair",
    "crypto_sign_seed_keypair",
    "crypto_sign",
    "crypto_sign_open",

    "randombytes",

	"crypto_generichash_BYTES",
	"crypto_generichash_BYTES_MIN",
	"crypto_generichash_BYTES_MAX",
	"crypto_generichash_KEYBYTES",
	"crypto_generichash_KEYBYTES_MIN",
	"crypto_generichash_KEYBYTES_MAX",
	"crypto_generichash",

	"crypto_shorthash_KEYBYTES",
	"crypto_shorthash_BYTES",
	"crypto_shorthash"
    "sodium_init",
]

# Initialize Sodium
sodium_init()
