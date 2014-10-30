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

from nacl import encoding
import nacl.c
from nacl.utils import EncryptedMessage, StringFixer, random


class PublicKey(encoding.Encodable, StringFixer, object):

    SIZE = nacl.c.crypto_box_PUBLICKEYBYTES

    def __init__(self, public_key, encoder=encoding.RawEncoder):
        self._public_key = encoder.decode(public_key)

        if len(self._public_key) != self.SIZE:
            raise ValueError("The public key must be exactly %s bytes long" %
                             self.SIZE)

    def __bytes__(self):
        return self._public_key


class PrivateKey(encoding.Encodable, StringFixer, object):

    SIZE = nacl.c.crypto_box_SECRETKEYBYTES

    def __init__(self, private_key, encoder=encoding.RawEncoder):
        # Decode the secret_key
        private_key = encoder.decode(private_key)

        # Verify that our seed is the proper size
        if len(private_key) != self.SIZE:
            raise ValueError(
                "The secret key must be exactly %d bytes long" % self.SIZE)

        # XXX: Do not depend on this to calculate the public key, it's details of crypto_box_keypair and may different from crypto_scalarmult_base.
        raw_public_key = nacl.c.crypto_scalarmult_base(private_key)

        self._private_key = private_key
        self.public_key = PublicKey(raw_public_key)

    def __bytes__(self):
        return self._private_key

    @classmethod
    def generate(cls):
        """
        Generates a random :class:`~nacl.public.PrivateKey` object

        :rtype: :class:`~nacl.public.PrivateKey`
        """
        raw_private_key, raw_public_key = nacl.c.crypto_box_keypair()
        private_key = cls(raw_private_key, encoder=encoding.RawEncoder)
        private_key.public_key = PublicKey(raw_public_key, encoder=encoding.RawEncoder)
        return private_key


class Box(encoding.Encodable, StringFixer, object):

    NONCE_SIZE = nacl.c.crypto_box_NONCEBYTES

    def __init__(self, private_key, public_key):
        if private_key and public_key:
            self._shared_key = nacl.c.crypto_box_beforenm(
                public_key.encode(encoder=encoding.RawEncoder),
                private_key.encode(encoder=encoding.RawEncoder),
            )
        else:
            self._shared_key = None

    def __bytes__(self):
        return self._shared_key

    @classmethod
    def decode(cls, encoded, encoder=encoding.RawEncoder):
        # Create an empty box
        box = cls(None, None)

        # Assign our decoded value to the shared key of the box
        box._shared_key = encoder.decode(encoded)

        return box

    def encrypt(self, plaintext, nonce, encoder=encoding.RawEncoder):

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("The nonce must be exactly %s bytes long" %
                             self.NONCE_SIZE)

        ciphertext = nacl.c.crypto_box_afternm(
            plaintext,
            nonce,
            self._shared_key,
        )

        encoded_nonce = encoder.encode(nonce)
        encoded_ciphertext = encoder.encode(ciphertext)

        return EncryptedMessage._from_parts(
            encoded_nonce,
            encoded_ciphertext,
            encoder.encode(nonce + ciphertext),
        )

    def decrypt(self, ciphertext, nonce=None, encoder=encoding.RawEncoder):

        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[:self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE:]

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("The nonce must be exactly %s bytes long" %
                             self.NONCE_SIZE)

        plaintext = nacl.c.crypto_box_open_afternm(
            ciphertext,
            nonce,
            self._shared_key,
        )

        return plaintext
