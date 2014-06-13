# Copyright 2014 Yoo-e and individual contributors
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

from __future__ import absolute_import
from __future__ import division

import nacl.c
from nacl.utils import EncryptedMessage, StringFixer, random

class Scalarmult(object):
    PRIVATE_KEY_SIZE = nacl.c.crypto_scalarmult_SCALARBYTES
    PUBLIC_KEY_SIZE = nacl.c.crypto_scalarmult_BYTES

    @classmethod
    def keypair(cls):
        pri = random(cls.PRIVATE_KEY_SIZE)
        pub = cls.public_key(pri)
        return pri, pub

    @classmethod
    def public_key(cls, pri):
        if len(pri) != cls.PRIVATE_KEY_SIZE:
            raise ValueError(
                    "The secret key must be exactly %d bytes long" % self.PRIVATE_KEY_SIZE)
        return nacl.c.crypto_scalarmult_base(pri)

    @classmethod
    def generate(cls, pri, pub):
        if len(pri) != cls.PRIVATE_KEY_SIZE:
            raise ValueError(
                    "The secret key must be exactly %d bytes long" % self.PRIVATE_KEY_SIZE)

        if len(pub) != cls.PUBLIC_KEY_SIZE:
            raise ValueError(
                    "The public key must be exactly %d bytes long" % self.PUBLIC_KEY_SIZE)

        return nacl.c.crypto_scalarmult(pri, pub)

