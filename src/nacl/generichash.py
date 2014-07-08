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

class Generichash(object):
	@classmethod
	def get_mac(cls, shared_key):
		return nacl.c.crypto_generichash(shared_key, None)

	@classmethod
	def crypto_generichash(cls, in_, key):
		return nacl.c.crypto_generichash(in_, key)

	@classmethod
	def get_passcode(cls, shared_key):
		return nacl.c.crypto_generichash(None, shared_key)
