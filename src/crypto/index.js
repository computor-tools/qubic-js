'use strict';

import Module from './libFourQ_K12.cjs';

const allocU8 = function (l, v) {
  let ptr = Module._malloc(l);
  let chunk = Module.HEAPU8.subarray(ptr, ptr + l);
  if (v) {
    chunk.set(v);
  }
  return chunk;
};

const allocU16 = function (l, v) {
  let ptr = Module._malloc(l);
  let chunk = Module.HEAPU16.subarray(ptr, ptr + l);
  chunk.set(v);
  return chunk;
};

/**
 * @namespace Crypto
 */

/**
 * A promise which always resolves to object with crypto functions.
 *
 * @constant {Promise<Crypto>}
 * @memberof module:qubic
 */
export const crypto = new Promise(function (resolve) {
  Module.onRuntimeInitialized = function () {
    /**
     * @memberof Crypto.schnorrq
     * @param {Uint8Array} secretKey
     * @returns {Uint8Array}
     */
    const generatePublicKey = function (secretKey) {
      const sk = allocU8(secretKey.length, secretKey);
      const pk = allocU8(32);

      const free = function () {
        Module._free(sk.byteOffset);
        Module._free(pk.byteOffset);
      };

      Module._SchnorrQ_KeyGeneration(sk.byteOffset, pk.byteOffset);
      free();
      return pk.slice();
    };

    /**
     * @memberof Crypto.schnorrq
     * @param {Uint8Array} secretKey
     * @param {Uint8Array} publicKey
     * @param {Uint8Array} message
     * @returns {Uint8Array}
     */
    const sign = function (secretKey, publicKey, message) {
      const sk = allocU8(secretKey.length, secretKey);
      const pk = allocU8(publicKey.length, publicKey);
      const m = allocU8(message.length, message);
      const s = allocU8(64);

      const free = function () {
        Module._free(sk.byteOffset);
        Module._free(pk.byteOffset);
        Module._free(m.byteOffset);
        Module._free(s.byteOffset);
      };

      Module._SchnorrQ_Sign(
        sk.byteOffset,
        pk.byteOffset,
        m.byteOffset,
        message.length,
        s.byteOffset
      );
      free();
      return s.slice();
    };

    /**
     * @memberof Crypto.schnorrq
     * @param {Uint8Array} publicKey
     * @param {Uint8Array} message
     * @param {Uint8Array} signature
     * @returns {number} 1 if valid, 0 if invalid
     */
    const verify = function (publicKey, message, signature) {
      const pk = allocU8(publicKey.length, publicKey);
      const m = allocU8(message.length, message);
      const s = allocU8(signature.length, signature);
      const v = allocU16(1, new Uint16Array(1));

      const free = function () {
        Module._free(pk.byteOffset);
        Module._free(m.byteOffset);
        Module._free(s.byteOffset);
        Module._free(v.byteOffset);
      };

      Module._SchnorrQ_Verify(
        pk.byteOffset,
        m.byteOffset,
        message.length,
        s.byteOffset,
        v.byteOffset
      );
      free();
      return v[0];
    };

    /**
     * @memberof Crypto.kex
     * @param {Uint8Array} secretKey
     * @returns {Uint8Array} Public key
     */
    const generateCompressedPublicKey = function (secretKey) {
      const sk = allocU8(secretKey.length, secretKey);
      const pk = allocU8(32);

      const free = function () {
        Module._free(sk.byteOffset);
        Module._free(pk.byteOffset);
      };

      Module._CompressedPublicKeyGeneration(sk.byteOffset, pk.byteOffset);
      free();
      return pk.slice();
    };

    /**
     * @memberof Crypto.kex
     * @param {Uint8Array} secretKey
     * @param {Uint8Array} publicKey
     * @returns {Uint8Array} Shared key
     */
    const compressedSecretAgreement = function (secretKey, publicKey) {
      const sk = allocU8(secretKey.length, secretKey);
      const pk = allocU8(publicKey.length, publicKey);
      const shk = allocU8(32);

      const free = function () {
        Module._free(sk.byteOffset);
        Module._free(pk.byteOffset);
        Module._free(shk.byteOffset);
      };

      Module._CompressedSecretAgreement(sk.byteOffset, pk.byteOffset, shk.byteOffset);
      free();
      return shk.slice();
    };

    /**
     * @memberof Crypto
     * @param {Uint8Array} input
     * @param {Uint8Array} output
     * @param {number} outputLength
     * @param {number} outputOffset
     */
    const K12 = function (input, output, outputLength, outputOffset = 0) {
      const i = allocU8(input.length, input);
      const o = allocU8(outputLength, new Uint8Array(outputLength));

      const free = function () {
        Module._free(i.byteOffset);
        Module._free(o.byteOffset);
      };

      Module._KangarooTwelve(i.byteOffset, input.length, o.byteOffset, outputLength, 0, 0);
      output.set(o, outputOffset);
      free();
    };

    resolve({
      /**
       * @namespace Crypto.schnorrq
       */
      schnorrq: {
        generatePublicKey,
        sign,
        verify,
      },
      /**
       * @namespace Crypto.kex
       */
      kex: {
        generateCompressedPublicKey,
        compressedSecretAgreement,
      },
      K12,
    });

    // const skA = [
    //   125, 62, 16, 133, 107, 33, 255, 186, 215, 151, 156, 9, 225, 118, 213, 175, 41, 138, 90, 128,
    //   198, 57, 176, 54, 161, 212, 50, 133, 236, 230, 186, 254,
    // ];
    // const pkA = generatePublicKey(skA);
    // console.log(pkA);

    // const skB = [
    //   125, 62, 16, 143, 107, 33, 255, 186, 215, 151, 156, 9, 225, 118, 213, 175, 41, 138, 90, 128,
    //   198, 57, 176, 54, 161, 212, 50, 133, 236, 230, 186, 0,
    // ];
    // const pkB = generatePublicKey(skB);

    // const hSkB = new Uint8Array(64);
    // K12(skB, hSkB, 64);
    // const shk = compressedSecretAgreement(skB, pkA);
    // console.log(shk);

    // const hSkA = new Uint8Array(64);
    // K12(skA, hSkA, 64);
    // const shk2 = compressedSecretAgreement(skA, pkB);
    // console.log(shk2);

    // const v = [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];
    // const aesCtr = new aesjs.ModeOfOperation.cbc(Buffer.from(shk), v);
    // const enc = aesCtr.encrypt(skB);
    // console.log(skB);
    // console.log(enc.toString());
    // const aesCtr2 = new aesjs.ModeOfOperation.cbc(Buffer.from(shk), v);
    // const dec = aesCtr2.decrypt(enc);
    // console.log(dec);

    // const message = new Uint8Array(1).fill(0).map(function (_, i) {
    //   return i;
    // });
    // const h = new Uint8Array(32);
    // k12(message, h, h.length);
    // console.log(Array.from(h));

    // const vector = {
    //   secretKey: [
    //     125, 62, 16, 133, 107, 33, 255, 186, 215, 151, 156, 9, 225, 118, 213, 175, 41, 138, 90, 128,
    //     198, 57, 176, 54, 161, 212, 50, 133, 236, 230, 186, 254,
    //   ],
    // };

    // const message = new Uint8Array(32).fill(1);
    // vector.publicKey = generatePublicKey(vector.secretKey);
    // vector.signature = sign(vector.secretKey, vector.publicKey, message);
    // vector.verified = verify(vector.publicKey, message, vector.signature);

    // console.log(vector.secretKey);
    // console.log(Array.from(vector.publicKey));
    // console.log(Array.from(message));
    // console.log(Array.from(vector.signature));

    // const t0 = performance.now();
    // const pairs = [];
    // for (let i = 0; i < 10; i++) {
    //   const secretKey = new Uint8Array(32).fill(1);
    //   pairs.push({
    //     secretKey,
    //     publicKey: generatePublicKey(secretKey),
    //   });
    // }
    // const t1 = performance.now();
    // console.log('Generating 10_000 public keys took', t1 - t0, 'ms');

    // const signatures = [];
    // for (let i = 0; i < pairs.length; i++) {
    //   signatures.push(sign(pairs[i].secretKey, pairs[i].publicKey, message));
    // }
    // const t2 = performance.now();
    // console.log('Generating 10_000 sigs took', t2 - t1, 'ms');

    // for (let i = 0; i < pairs.length; i++) {
    //   console.log(verify(pairs[i].publicKey, message, signatures[i]));
    // }
    // const t3 = performance.now();
    // console.log('Verifying 10_000 sigs took', t3 - t2, 'ms');
  };
});
