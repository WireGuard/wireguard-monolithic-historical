/*! SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
window["WireGuard"] = {
	"generateKeypair": function() {
		var privateKey = Module["_malloc"](32);
		var publicKey = Module["_malloc"](32);
		Module["_curve25519_generate_private"](privateKey);
		Module["_curve25519_generate_public"](publicKey, privateKey);
		var privateBase64 = Module["_malloc"](45);
		var publicBase64 = Module["_malloc"](45);
		Module["_key_to_base64"](privateBase64, privateKey);
		Module["_key_to_base64"](publicBase64, publicKey);
		Module["_free"](privateKey);
		Module["_free"](publicKey);
		var keypair = {
			publicKey: Module["Pointer_stringify"](publicBase64),
			privateKey: Module["Pointer_stringify"](privateBase64)
		};
		Module["_free"](privateBase64);
		Module["_free"](publicBase64);
		return keypair;
	}
};
