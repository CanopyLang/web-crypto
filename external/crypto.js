// Canopy Web Crypto FFI — Web Crypto API bindings
//
// Imported in Crypto modules via:
//   foreign import javascript "external/crypto.js" as CryptoFFI
//
// Key types (AesKey, HmacKey, etc.) are opaque nullary constructors in Canopy.
// On the JS side, the CryptoKey object IS the value — no wrapping needed.
// The type system enforces safety; the JS side just passes CryptoKey objects around.


// ============================================================================
// RESULT CONSTRUCTORS
// ============================================================================

function _Crypto_ok(a) { return __canopy_debug ? { $: 'Ok', a: a } : { $: 0, a: a }; }
function _Crypto_err(a) { return __canopy_debug ? { $: 'Err', a: a } : { $: 1, a: a }; }


// ============================================================================
// ERROR CONSTRUCTORS
// ============================================================================

function _Crypto_operationFailed(msg)
{
	return __canopy_debug ? { $: 'OperationFailed', a: msg } : { $: 0, a: msg };
}

function _Crypto_invalidKey(msg)
{
	return __canopy_debug ? { $: 'InvalidKey', a: msg } : { $: 1, a: msg };
}

function _Crypto_invalidData(msg)
{
	return __canopy_debug ? { $: 'InvalidData', a: msg } : { $: 2, a: msg };
}

function _Crypto_notSupported(msg)
{
	return __canopy_debug ? { $: 'NotSupported', a: msg } : { $: 3, a: msg };
}


// ============================================================================
// MAYBE CONSTRUCTORS
// ============================================================================

var _Crypto_nothing = __canopy_debug ? { $: 'Nothing' } : { $: 1 };
function _Crypto_just(a) { return __canopy_debug ? { $: 'Just', a: a } : { $: 0, a: a }; }


// ============================================================================
// HELPER: BYTES <-> ARRAYBUFFER
// ============================================================================

function _Crypto_bytesToUint8(dv)
{
	return new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
}

function _Crypto_uint8ToBytes(u8)
{
	return new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
}

function _Crypto_abToBytes(ab)
{
	return new DataView(ab);
}


// ============================================================================
// HELPER: ALGORITHM NAME MAPPING
// ============================================================================

function _Crypto_hashAlgoName(hashAlgo)
{
	var tag = __canopy_debug ? hashAlgo.$ : hashAlgo;
	if (__canopy_debug) {
		switch (tag) {
			case 'SHA1': return 'SHA-1';
			case 'SHA256': return 'SHA-256';
			case 'SHA384': return 'SHA-384';
			case 'SHA512': return 'SHA-512';
			default: return 'SHA-256';
		}
	}
	switch (tag) {
		case 0: return 'SHA-1';
		case 1: return 'SHA-256';
		case 2: return 'SHA-384';
		case 3: return 'SHA-512';
		default: return 'SHA-256';
	}
}

function _Crypto_aesAlgoName(aesAlgo)
{
	var tag = __canopy_debug ? aesAlgo.$ : aesAlgo;
	if (__canopy_debug) {
		switch (tag) {
			case 'AesGcm': return 'AES-GCM';
			case 'AesCbc': return 'AES-CBC';
			case 'AesCtr': return 'AES-CTR';
			default: return 'AES-GCM';
		}
	}
	switch (tag) {
		case 0: return 'AES-GCM';
		case 1: return 'AES-CBC';
		case 2: return 'AES-CTR';
		default: return 'AES-GCM';
	}
}

function _Crypto_aesKeyLengthBits(keyLen)
{
	var tag = __canopy_debug ? keyLen.$ : keyLen;
	if (__canopy_debug) {
		switch (tag) {
			case 'Aes128': return 128;
			case 'Aes192': return 192;
			case 'Aes256': return 256;
			default: return 256;
		}
	}
	switch (tag) {
		case 0: return 128;
		case 1: return 192;
		case 2: return 256;
		default: return 256;
	}
}

function _Crypto_rsaKeyLengthBits(keyLen)
{
	var tag = __canopy_debug ? keyLen.$ : keyLen;
	if (__canopy_debug) {
		switch (tag) {
			case 'Rsa2048': return 2048;
			case 'Rsa4096': return 4096;
			default: return 2048;
		}
	}
	switch (tag) {
		case 0: return 2048;
		case 1: return 4096;
		default: return 2048;
	}
}

function _Crypto_ecCurveName(curve)
{
	var tag = __canopy_debug ? curve.$ : curve;
	if (__canopy_debug) {
		switch (tag) {
			case 'P256': return 'P-256';
			case 'P384': return 'P-384';
			case 'P521': return 'P-521';
			default: return 'P-256';
		}
	}
	switch (tag) {
		case 0: return 'P-256';
		case 1: return 'P-384';
		case 2: return 'P-521';
		default: return 'P-256';
	}
}

function _Crypto_rsaSignAlgoName(algo)
{
	var tag = __canopy_debug ? algo.$ : algo;
	if (__canopy_debug) {
		switch (tag) {
			case 'RsaPss': return 'RSA-PSS';
			case 'RsaPkcs1': return 'RSASSA-PKCS1-v1_5';
			default: return 'RSA-PSS';
		}
	}
	switch (tag) {
		case 0: return 'RSA-PSS';
		case 1: return 'RSASSA-PKCS1-v1_5';
		default: return 'RSA-PSS';
	}
}

function _Crypto_keyFormatStr(fmt)
{
	var tag = __canopy_debug ? fmt.$ : fmt;
	if (__canopy_debug) {
		switch (tag) {
			case 'Raw': return 'raw';
			case 'Pkcs8': return 'pkcs8';
			case 'Spki': return 'spki';
			case 'Jwk': return 'jwk';
			default: return 'raw';
		}
	}
	switch (tag) {
		case 0: return 'raw';
		case 1: return 'pkcs8';
		case 2: return 'spki';
		case 3: return 'jwk';
		default: return 'raw';
	}
}


// ============================================================================
// CRYPTO: RANDOM
// ============================================================================

/**
 * @canopy-type Int -> Task Error Bytes
 * @name randomBytes
 */
function randomBytes(n)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var arr = new Uint8Array(n);
			crypto.getRandomValues(arr);
			callback(_Scheduler_succeed(_Crypto_uint8ToBytes(arr)));
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
}

/**
 * @canopy-type Task Error String
 * @name randomUUID
 */
var randomUUID = _Scheduler_binding(function(callback)
{
	try
	{
		callback(_Scheduler_succeed(crypto.randomUUID()));
	}
	catch(e)
	{
		callback(_Scheduler_fail(_Crypto_notSupported(e.message)));
	}
});

/**
 * @canopy-type Task Never Capability.Available
 * @name isAvailable
 */
var isAvailable = _Scheduler_binding(function(callback)
{
	try {
		if (typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined') {
			callback(_Scheduler_succeed({ $: 'Supported' }));
		} else {
			callback(_Scheduler_succeed({ $: 'Unsupported' }));
		}
	} catch (e) {
		callback(_Scheduler_succeed({ $: 'Unsupported' }));
	}
});


// ============================================================================
// CRYPTO.HASH: DIGEST
// ============================================================================

/**
 * @canopy-type HashAlgorithm -> Bytes -> Task Error Bytes
 * @name digest
 */
var digest = F2(function(hashAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_hashAlgoName(hashAlgo);
		var data = _Crypto_bytesToUint8(bytes);
		crypto.subtle.digest(algoName, data).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});


// ============================================================================
// CRYPTO.HMAC
// ============================================================================

/**
 * @canopy-type HashAlgorithm -> Task Error HmacKey
 * @name hmacGenerateKey
 */
function hmacGenerateKey(hashAlgo)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_hashAlgoName(hashAlgo);
		crypto.subtle.generateKey(
			{ name: 'HMAC', hash: algoName },
			true,
			['sign', 'verify']
		).then(function(key)
		{
			callback(_Scheduler_succeed(key));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
}

/**
 * @canopy-type HashAlgorithm -> Bytes -> Task Error HmacKey
 * @name hmacImportKey
 */
var hmacImportKey = F2(function(hashAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_hashAlgoName(hashAlgo);
		var data = _Crypto_bytesToUint8(bytes);
		crypto.subtle.importKey(
			'raw', data,
			{ name: 'HMAC', hash: algoName },
			true,
			['sign', 'verify']
		).then(function(key)
		{
			callback(_Scheduler_succeed(key));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_invalidKey(e.message)));
		});
	});
});

/**
 * @canopy-type HmacKey -> Task Error Bytes
 * @name hmacExportKey
 */
function hmacExportKey(ck)
{
	return _Scheduler_binding(function(callback)
	{
		crypto.subtle.exportKey('raw', ck).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
}

/**
 * @canopy-type HmacKey -> Bytes -> Task Error Bytes
 * @name hmacSign
 */
var hmacSign = F2(function(ck, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var data = _Crypto_bytesToUint8(bytes);
		crypto.subtle.sign('HMAC', ck, data).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type HmacKey -> Bytes -> Bytes -> Task Error Bool
 * @name hmacVerify
 */
var hmacVerify = F3(function(ck, data, sig)
{
	return _Scheduler_binding(function(callback)
	{
		var dataArr = _Crypto_bytesToUint8(data);
		var sigArr = _Crypto_bytesToUint8(sig);
		crypto.subtle.verify('HMAC', ck, sigArr, dataArr).then(function(valid)
		{
			callback(_Scheduler_succeed(valid));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});


// ============================================================================
// CRYPTO.ENCRYPT: AES
// ============================================================================

/**
 * @canopy-type AesAlgorithm -> AesKeyLength -> Task Error AesKey
 * @name generateAesKey
 */
var generateAesKey = F2(function(aesAlgo, keyLen)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_aesAlgoName(aesAlgo);
		var bits = _Crypto_aesKeyLengthBits(keyLen);
		crypto.subtle.generateKey(
			{ name: algoName, length: bits },
			true,
			['encrypt', 'decrypt']
		).then(function(key)
		{
			callback(_Scheduler_succeed(key));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type AesAlgorithm -> Bytes -> Task Error AesKey
 * @name importAesKeyRaw
 */
var importAesKeyRaw = F2(function(aesAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_aesAlgoName(aesAlgo);
		var data = _Crypto_bytesToUint8(bytes);
		crypto.subtle.importKey(
			'raw', data,
			{ name: algoName },
			true,
			['encrypt', 'decrypt']
		).then(function(key)
		{
			callback(_Scheduler_succeed(key));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_invalidKey(e.message)));
		});
	});
});

/**
 * @canopy-type AesKey -> Task Error Bytes
 * @name exportAesKeyRaw
 */
function exportAesKeyRaw(ck)
{
	return _Scheduler_binding(function(callback)
	{
		crypto.subtle.exportKey('raw', ck).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
}

/**
 * @canopy-type AesKey -> Bytes -> Maybe Bytes -> Task Error EncryptedData
 * @name encryptAesGcm
 */
var encryptAesGcm = F3(function(ck, plaintext, maybeAad)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var data = _Crypto_bytesToUint8(plaintext);
			var iv = new Uint8Array(12);
			crypto.getRandomValues(iv);
			var params = { name: 'AES-GCM', iv: iv };

			var hasAad = __canopy_debug ? (maybeAad.$ === 'Just') : (maybeAad.$ === 0);
			if (hasAad) { params.additionalData = _Crypto_bytesToUint8(maybeAad.a); }

			crypto.subtle.encrypt(params, ck, data).then(function(ab)
			{
				var result = new Uint8Array(ab);
				var cipherLen = result.byteLength - 16;
				var ciphertext = result.slice(0, cipherLen);
				var tag = result.slice(cipherLen);
				callback(_Scheduler_succeed({
					ciphertext: _Crypto_uint8ToBytes(ciphertext),
					iv: _Crypto_uint8ToBytes(iv),
					tag: _Crypto_just(_Crypto_uint8ToBytes(tag))
				}));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type AesKey -> EncryptedData -> Maybe Bytes -> Task Error Bytes
 * @name decryptAesGcm
 */
var decryptAesGcm = F3(function(ck, encData, maybeAad)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var ct = _Crypto_bytesToUint8(encData.ciphertext);
			var ivArr = _Crypto_bytesToUint8(encData.iv);
			var params = { name: 'AES-GCM', iv: ivArr };

			var hasAad = __canopy_debug ? (maybeAad.$ === 'Just') : (maybeAad.$ === 0);
			if (hasAad) { params.additionalData = _Crypto_bytesToUint8(maybeAad.a); }

			var hasTag = __canopy_debug ? (encData.tag.$ === 'Just') : (encData.tag.$ === 0);
			var combined;
			if (hasTag) {
				var tagArr = _Crypto_bytesToUint8(encData.tag.a);
				combined = new Uint8Array(ct.byteLength + tagArr.byteLength);
				combined.set(ct, 0);
				combined.set(tagArr, ct.byteLength);
			} else {
				combined = ct;
			}

			crypto.subtle.decrypt(params, ck, combined).then(function(ab)
			{
				callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_invalidData(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type AesKey -> Bytes -> Task Error EncryptedData
 * @name encryptAesCbc
 */
var encryptAesCbc = F2(function(ck, plaintext)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var data = _Crypto_bytesToUint8(plaintext);
			var iv = new Uint8Array(16);
			crypto.getRandomValues(iv);
			crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, ck, data).then(function(ab)
			{
				callback(_Scheduler_succeed({
					ciphertext: _Crypto_abToBytes(ab),
					iv: _Crypto_uint8ToBytes(iv),
					tag: _Crypto_nothing
				}));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type AesKey -> EncryptedData -> Task Error Bytes
 * @name decryptAesCbc
 */
var decryptAesCbc = F2(function(ck, encData)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var ct = _Crypto_bytesToUint8(encData.ciphertext);
			var ivArr = _Crypto_bytesToUint8(encData.iv);
			crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivArr }, ck, ct).then(function(ab)
			{
				callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_invalidData(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type AesKey -> Bytes -> Task Error EncryptedData
 * @name encryptAesCtr
 */
var encryptAesCtr = F2(function(ck, plaintext)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var data = _Crypto_bytesToUint8(plaintext);
			var counter = new Uint8Array(16);
			crypto.getRandomValues(counter);
			crypto.subtle.encrypt({ name: 'AES-CTR', counter: counter, length: 64 }, ck, data).then(function(ab)
			{
				callback(_Scheduler_succeed({
					ciphertext: _Crypto_abToBytes(ab),
					iv: _Crypto_uint8ToBytes(counter),
					tag: _Crypto_nothing
				}));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type AesKey -> EncryptedData -> Task Error Bytes
 * @name decryptAesCtr
 */
var decryptAesCtr = F2(function(ck, encData)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var ct = _Crypto_bytesToUint8(encData.ciphertext);
			var counter = _Crypto_bytesToUint8(encData.iv);
			crypto.subtle.decrypt({ name: 'AES-CTR', counter: counter, length: 64 }, ck, ct).then(function(ab)
			{
				callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_invalidData(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});


// ============================================================================
// CRYPTO.ENCRYPT: RSA-OAEP
// ============================================================================

/**
 * @canopy-type RsaKeyLength -> HashAlgorithm -> Task Error RsaKeyPair
 * @name generateRsaKeyPairWith
 */
var generateRsaKeyPairWith = F2(function(rsaKeyLen, hashAlgo)
{
	return _Scheduler_binding(function(callback)
	{
		var bits = _Crypto_rsaKeyLengthBits(rsaKeyLen);
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		crypto.subtle.generateKey(
			{
				name: 'RSA-OAEP',
				modulusLength: bits,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: hashName
			},
			true,
			['encrypt', 'decrypt']
		).then(function(keyPair)
		{
			callback(_Scheduler_succeed({
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			}));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type RsaPublicKey -> Bytes -> Task Error Bytes
 * @name encryptRsa
 */
var encryptRsa = F2(function(ck, plaintext)
{
	return _Scheduler_binding(function(callback)
	{
		var data = _Crypto_bytesToUint8(plaintext);
		crypto.subtle.encrypt({ name: 'RSA-OAEP' }, ck, data).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type RsaPrivateKey -> Bytes -> Task Error Bytes
 * @name decryptRsa
 */
var decryptRsa = F2(function(ck, ciphertext)
{
	return _Scheduler_binding(function(callback)
	{
		var data = _Crypto_bytesToUint8(ciphertext);
		crypto.subtle.decrypt({ name: 'RSA-OAEP' }, ck, data).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_invalidData(e.message)));
		});
	});
});


// ============================================================================
// CRYPTO.SIGN: ECDSA
// ============================================================================

/**
 * @canopy-type EcCurve -> Task Error EcdsaKeyPair
 * @name generateEcdsaKeyPair
 */
function generateEcdsaKeyPair(curve)
{
	return _Scheduler_binding(function(callback)
	{
		var curveName = _Crypto_ecCurveName(curve);
		crypto.subtle.generateKey(
			{ name: 'ECDSA', namedCurve: curveName },
			true,
			['sign', 'verify']
		).then(function(keyPair)
		{
			callback(_Scheduler_succeed({
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			}));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
}

/**
 * @canopy-type EcdsaPrivateKey -> HashAlgorithm -> Bytes -> Task Error Bytes
 * @name signEcdsa
 */
var signEcdsa = F3(function(ck, hashAlgo, data)
{
	return _Scheduler_binding(function(callback)
	{
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		var dataArr = _Crypto_bytesToUint8(data);
		crypto.subtle.sign({ name: 'ECDSA', hash: hashName }, ck, dataArr).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type EcdsaPublicKey -> HashAlgorithm -> Bytes -> Bytes -> Task Error Bool
 * @name verifyEcdsa
 */
var verifyEcdsa = F4(function(ck, hashAlgo, data, sig)
{
	return _Scheduler_binding(function(callback)
	{
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		var dataArr = _Crypto_bytesToUint8(data);
		var sigArr = _Crypto_bytesToUint8(sig);
		crypto.subtle.verify({ name: 'ECDSA', hash: hashName }, ck, sigArr, dataArr).then(function(valid)
		{
			callback(_Scheduler_succeed(valid));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});


// ============================================================================
// CRYPTO.SIGN: RSA
// ============================================================================

/**
 * @canopy-type RsaSignAlgorithm -> RsaKeyLength -> HashAlgorithm -> Task Error RsaSigningKeyPair
 * @name generateRsaSigningKeyPair
 */
var generateRsaSigningKeyPair = F3(function(signAlgo, rsaKeyLen, hashAlgo)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_rsaSignAlgoName(signAlgo);
		var bits = _Crypto_rsaKeyLengthBits(rsaKeyLen);
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		crypto.subtle.generateKey(
			{
				name: algoName,
				modulusLength: bits,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: hashName
			},
			true,
			['sign', 'verify']
		).then(function(keyPair)
		{
			callback(_Scheduler_succeed({
				publicKey: keyPair.publicKey,
				privateKey: keyPair.privateKey
			}));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type RsaSigningPrivateKey -> Int -> Bytes -> Task Error Bytes
 * @name signRsaPss
 */
var signRsaPss = F3(function(ck, saltLen, data)
{
	return _Scheduler_binding(function(callback)
	{
		var dataArr = _Crypto_bytesToUint8(data);
		crypto.subtle.sign({ name: 'RSA-PSS', saltLength: saltLen }, ck, dataArr).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type RsaSigningPublicKey -> Int -> Bytes -> Bytes -> Task Error Bool
 * @name verifyRsaPss
 */
var verifyRsaPss = F4(function(ck, saltLen, data, sig)
{
	return _Scheduler_binding(function(callback)
	{
		var dataArr = _Crypto_bytesToUint8(data);
		var sigArr = _Crypto_bytesToUint8(sig);
		crypto.subtle.verify({ name: 'RSA-PSS', saltLength: saltLen }, ck, sigArr, dataArr).then(function(valid)
		{
			callback(_Scheduler_succeed(valid));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type RsaSigningPrivateKey -> Bytes -> Task Error Bytes
 * @name signRsaPkcs1
 */
var signRsaPkcs1 = F2(function(ck, data)
{
	return _Scheduler_binding(function(callback)
	{
		var dataArr = _Crypto_bytesToUint8(data);
		crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, ck, dataArr).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type RsaSigningPublicKey -> Bytes -> Bytes -> Task Error Bool
 * @name verifyRsaPkcs1
 */
var verifyRsaPkcs1 = F3(function(ck, data, sig)
{
	return _Scheduler_binding(function(callback)
	{
		var dataArr = _Crypto_bytesToUint8(data);
		var sigArr = _Crypto_bytesToUint8(sig);
		crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, ck, sigArr, dataArr).then(function(valid)
		{
			callback(_Scheduler_succeed(valid));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});


// ============================================================================
// CRYPTO.KEY: EXPORT
// ============================================================================

/**
 * @canopy-type KeyFormat -> key -> Task Error Bytes
 * @name exportKeyBytes
 */
var exportKeyBytes = F2(function(fmt, ck)
{
	return _Scheduler_binding(function(callback)
	{
		var format = _Crypto_keyFormatStr(fmt);
		crypto.subtle.exportKey(format, ck).then(function(ab)
		{
			callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
});

/**
 * @canopy-type key -> Task Error JsonWebKey
 * @name exportKeyJwk
 */
function exportKeyJwk(ck)
{
	return _Scheduler_binding(function(callback)
	{
		crypto.subtle.exportKey('jwk', ck).then(function(jwk)
		{
			callback(_Scheduler_succeed(jwk));
		}).catch(function(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		});
	});
}


// ============================================================================
// CRYPTO.KEY: IMPORT
// ============================================================================

var _Crypto_importKeyGeneric = function(format, algo, keyData, extractable, usages, callback)
{
	var data;
	if (format === 'jwk') {
		data = keyData;
	} else {
		data = _Crypto_bytesToUint8(keyData);
	}

	crypto.subtle.importKey(format, data, algo, extractable, usages).then(function(key)
	{
		callback(_Scheduler_succeed(key));
	}).catch(function(e)
	{
		callback(_Scheduler_fail(_Crypto_invalidKey(e.message)));
	});
};

/**
 * @canopy-type AesAlgorithm -> Bytes -> Task Error AesKey
 * @name importAesRaw
 */
var importAesRaw = F2(function(aesAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_aesAlgoName(aesAlgo);
		_Crypto_importKeyGeneric('raw', { name: algoName }, bytes, true, ['encrypt', 'decrypt'], callback);
	});
});

/**
 * @canopy-type AesAlgorithm -> JsonWebKey -> Task Error AesKey
 * @name importAesJwk
 */
var importAesJwk = F2(function(aesAlgo, jwk)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_aesAlgoName(aesAlgo);
		_Crypto_importKeyGeneric('jwk', { name: algoName }, jwk, true, ['encrypt', 'decrypt'], callback);
	});
});

/**
 * @canopy-type HashAlgorithm -> Bytes -> Task Error RsaPublicKey
 * @name importRsaPublicSpki
 */
var importRsaPublicSpki = F2(function(hashAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		_Crypto_importKeyGeneric('spki', { name: 'RSA-OAEP', hash: hashName }, bytes, true, ['encrypt'], callback);
	});
});

/**
 * @canopy-type HashAlgorithm -> JsonWebKey -> Task Error RsaPublicKey
 * @name importRsaPublicJwk
 */
var importRsaPublicJwk = F2(function(hashAlgo, jwk)
{
	return _Scheduler_binding(function(callback)
	{
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		_Crypto_importKeyGeneric('jwk', { name: 'RSA-OAEP', hash: hashName }, jwk, true, ['encrypt'], callback);
	});
});

/**
 * @canopy-type HashAlgorithm -> Bytes -> Task Error RsaPrivateKey
 * @name importRsaPrivatePkcs8
 */
var importRsaPrivatePkcs8 = F2(function(hashAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		_Crypto_importKeyGeneric('pkcs8', { name: 'RSA-OAEP', hash: hashName }, bytes, true, ['decrypt'], callback);
	});
});

/**
 * @canopy-type HashAlgorithm -> JsonWebKey -> Task Error RsaPrivateKey
 * @name importRsaPrivateJwk
 */
var importRsaPrivateJwk = F2(function(hashAlgo, jwk)
{
	return _Scheduler_binding(function(callback)
	{
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		_Crypto_importKeyGeneric('jwk', { name: 'RSA-OAEP', hash: hashName }, jwk, true, ['decrypt'], callback);
	});
});

/**
 * @canopy-type EcCurve -> Bytes -> Task Error EcdsaPublicKey
 * @name importEcdsaPublicSpki
 */
var importEcdsaPublicSpki = F2(function(curve, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var curveName = _Crypto_ecCurveName(curve);
		_Crypto_importKeyGeneric('spki', { name: 'ECDSA', namedCurve: curveName }, bytes, true, ['verify'], callback);
	});
});

/**
 * @canopy-type EcCurve -> JsonWebKey -> Task Error EcdsaPublicKey
 * @name importEcdsaPublicJwk
 */
var importEcdsaPublicJwk = F2(function(curve, jwk)
{
	return _Scheduler_binding(function(callback)
	{
		var curveName = _Crypto_ecCurveName(curve);
		_Crypto_importKeyGeneric('jwk', { name: 'ECDSA', namedCurve: curveName }, jwk, true, ['verify'], callback);
	});
});

/**
 * @canopy-type EcCurve -> Bytes -> Task Error EcdsaPrivateKey
 * @name importEcdsaPrivatePkcs8
 */
var importEcdsaPrivatePkcs8 = F2(function(curve, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var curveName = _Crypto_ecCurveName(curve);
		_Crypto_importKeyGeneric('pkcs8', { name: 'ECDSA', namedCurve: curveName }, bytes, true, ['sign'], callback);
	});
});

/**
 * @canopy-type EcCurve -> JsonWebKey -> Task Error EcdsaPrivateKey
 * @name importEcdsaPrivateJwk
 */
var importEcdsaPrivateJwk = F2(function(curve, jwk)
{
	return _Scheduler_binding(function(callback)
	{
		var curveName = _Crypto_ecCurveName(curve);
		_Crypto_importKeyGeneric('jwk', { name: 'ECDSA', namedCurve: curveName }, jwk, true, ['sign'], callback);
	});
});

/**
 * @canopy-type RsaSignAlgorithm -> HashAlgorithm -> Bytes -> Task Error RsaSigningPublicKey
 * @name importRsaSigningPublicSpki
 */
var importRsaSigningPublicSpki = F3(function(signAlgo, hashAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_rsaSignAlgoName(signAlgo);
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		_Crypto_importKeyGeneric('spki', { name: algoName, hash: hashName }, bytes, true, ['verify'], callback);
	});
});

/**
 * @canopy-type RsaSignAlgorithm -> HashAlgorithm -> Bytes -> Task Error RsaSigningPrivateKey
 * @name importRsaSigningPrivatePkcs8
 */
var importRsaSigningPrivatePkcs8 = F3(function(signAlgo, hashAlgo, bytes)
{
	return _Scheduler_binding(function(callback)
	{
		var algoName = _Crypto_rsaSignAlgoName(signAlgo);
		var hashName = _Crypto_hashAlgoName(hashAlgo);
		_Crypto_importKeyGeneric('pkcs8', { name: algoName, hash: hashName }, bytes, true, ['sign'], callback);
	});
});


// ============================================================================
// CRYPTO.KEY: DERIVATION
// ============================================================================

/**
 * @canopy-type HashAlgorithm -> Bytes -> Int -> Int -> String -> AesAlgorithm -> Task Error AesKey
 * @name deriveKeyPbkdf2Wrapped
 */
var deriveKeyPbkdf2Wrapped = F6(function(hashAlgo, salt, iterations, keyLenBits, password, aesAlgo)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var enc = new TextEncoder();
			var passBytes = enc.encode(password);
			var saltArr = _Crypto_bytesToUint8(salt);
			var hashName = _Crypto_hashAlgoName(hashAlgo);
			var aesAlgoName = _Crypto_aesAlgoName(aesAlgo);

			crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveKey']).then(function(baseKey)
			{
				return crypto.subtle.deriveKey(
					{ name: 'PBKDF2', salt: saltArr, iterations: iterations, hash: hashName },
					baseKey,
					{ name: aesAlgoName, length: keyLenBits },
					true,
					['encrypt', 'decrypt']
				);
			}).then(function(key)
			{
				callback(_Scheduler_succeed(key));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type HashAlgorithm -> Bytes -> Int -> Int -> String -> Task Error Bytes
 * @name deriveBitsPbkdf2
 */
var deriveBitsPbkdf2 = F5(function(hashAlgo, salt, iterations, numBytes, password)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var enc = new TextEncoder();
			var passBytes = enc.encode(password);
			var saltArr = _Crypto_bytesToUint8(salt);
			var hashName = _Crypto_hashAlgoName(hashAlgo);

			crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']).then(function(baseKey)
			{
				return crypto.subtle.deriveBits(
					{ name: 'PBKDF2', salt: saltArr, iterations: iterations, hash: hashName },
					baseKey,
					numBytes * 8
				);
			}).then(function(ab)
			{
				callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type HashAlgorithm -> Bytes -> Bytes -> Int -> Bytes -> AesAlgorithm -> Task Error AesKey
 * @name deriveKeyHkdf
 */
var deriveKeyHkdf = F6(function(hashAlgo, salt, info, keyLenBits, ikm, aesAlgo)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var saltArr = _Crypto_bytesToUint8(salt);
			var infoArr = _Crypto_bytesToUint8(info);
			var ikmArr = _Crypto_bytesToUint8(ikm);
			var hashName = _Crypto_hashAlgoName(hashAlgo);
			var aesAlgoName = _Crypto_aesAlgoName(aesAlgo);

			crypto.subtle.importKey('raw', ikmArr, 'HKDF', false, ['deriveKey']).then(function(baseKey)
			{
				return crypto.subtle.deriveKey(
					{ name: 'HKDF', salt: saltArr, info: infoArr, hash: hashName },
					baseKey,
					{ name: aesAlgoName, length: keyLenBits },
					true,
					['encrypt', 'decrypt']
				);
			}).then(function(key)
			{
				callback(_Scheduler_succeed(key));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});

/**
 * @canopy-type HashAlgorithm -> Bytes -> Bytes -> Int -> Bytes -> Task Error Bytes
 * @name deriveBitsHkdf
 */
var deriveBitsHkdf = F5(function(hashAlgo, salt, info, numBytes, ikm)
{
	return _Scheduler_binding(function(callback)
	{
		try
		{
			var saltArr = _Crypto_bytesToUint8(salt);
			var infoArr = _Crypto_bytesToUint8(info);
			var ikmArr = _Crypto_bytesToUint8(ikm);
			var hashName = _Crypto_hashAlgoName(hashAlgo);

			crypto.subtle.importKey('raw', ikmArr, 'HKDF', false, ['deriveBits']).then(function(baseKey)
			{
				return crypto.subtle.deriveBits(
					{ name: 'HKDF', salt: saltArr, info: infoArr, hash: hashName },
					baseKey,
					numBytes * 8
				);
			}).then(function(ab)
			{
				callback(_Scheduler_succeed(_Crypto_abToBytes(ab)));
			}).catch(function(e)
			{
				callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
			});
		}
		catch(e)
		{
			callback(_Scheduler_fail(_Crypto_operationFailed(e.message)));
		}
	});
});


// ============================================================================
// HELPER: TEXT ENCODE/DECODE FOR STRING CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * @canopy-type String -> Bytes
 * @name stringToBytes
 */
function stringToBytes(str)
{
	var enc = new TextEncoder();
	var uint8 = enc.encode(str);
	return _Crypto_uint8ToBytes(uint8);
}

/**
 * @canopy-type Bytes -> Result Error String
 * @name bytesToString
 */
function bytesToString(bytes)
{
	try
	{
		var dec = new TextDecoder('utf-8', { fatal: true });
		var uint8 = _Crypto_bytesToUint8(bytes);
		return _Crypto_ok(dec.decode(uint8));
	}
	catch(e)
	{
		return _Crypto_err(_Crypto_invalidData(e.message));
	}
}

/**
 * @canopy-type Bytes -> String
 * @name bytesToHex
 */
function bytesToHex(bytes)
{
	var u8 = _Crypto_bytesToUint8(bytes);
	var hex = '';
	for (var i = 0; i < u8.length; i++)
	{
		hex += u8[i].toString(16).padStart(2, '0');
	}
	return hex;
}
