'use strict';

import { crypto } from './crypto/index.js';
import { bytesToShiftedHex, shiftedHexToBytes, HEX_CHARS_PER_BYTE } from './utils/hex.js';

const SEED_ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
export const SEED_IN_LOWERCASE_LATIN_LENGTH = 55;
const PRIVATE_KEY_LENGTH = 32;
export const PUBLIC_KEY_LENGTH = 32;
export const PUBLIC_KEY_LENGTH_IN_HEX = PUBLIC_KEY_LENGTH * HEX_CHARS_PER_BYTE;
export const CHECKSUM_LENGTH = 3;
const SEED_CHECKSUM_LENGTH = 1.5;

const seedToBytes = function (seed) {
  const bytes = new Uint8Array(seed.length);
  for (let i = 0; i < seed.length; i++) {
    bytes[i] = SEED_ALPHABET.indexOf(seed[i]);
  }
  return bytes;
};

/**
 * Generates a private key from seed.
 *
 * @function privateKey
 * @memberof module:qubic
 * @param {string} seed - Seed in 55 lowercase latin chars.
 * @param {number} index - Identity index.
 * @param {Crypto.K12} K12 - K12 function.
 * @returns {Uint8Array} Private key bytes.
 */
export const privateKey = function (seed, index, K12) {
  seed = seedToBytes(seed);
  const preimage = seed.slice();

  while (index-- > 0) {
    for (let i = 0; i < preimage.length; i++) {
      if (++preimage[i] > SEED_ALPHABET.length) {
        preimage[i] = 1;
      } else {
        break;
      }
    }
  }

  const key = new Uint8Array(PRIVATE_KEY_LENGTH);
  K12(preimage, key, PRIVATE_KEY_LENGTH);
  return key;
};

/**
 * Creates an identity with checksum.
 *
 * @function identity
 * @memberof module:qubic
 * @param {string} seed - Seed in 55 lowercase latin chars.
 * @param {number} index - Identity index.
 * @returns {Promise<string>} Identity with checksum in uppercase hex.
 */
export const identity = function (seed, index) {
  if (!new RegExp(`^[a-z]{${SEED_IN_LOWERCASE_LATIN_LENGTH}}$`).test(seed)) {
    throw new Error(
      `Invalid seed. Must be ${SEED_IN_LOWERCASE_LATIN_LENGTH} lowercase latin chars.`
    );
  }

  if (!Number.isInteger(index) || index < 0) {
    throw new Error('Illegal index.');
  }

  return crypto.then(function ({ schnorrq, K12 }) {
    const publicKeyWithChecksum = new Uint8Array(PUBLIC_KEY_LENGTH + CHECKSUM_LENGTH);
    publicKeyWithChecksum.set(schnorrq.generatePublicKey(privateKey(seed, index, K12)));
    K12(
      publicKeyWithChecksum.subarray(0, PUBLIC_KEY_LENGTH),
      publicKeyWithChecksum,
      CHECKSUM_LENGTH,
      PUBLIC_KEY_LENGTH
    );
    return bytesToShiftedHex(publicKeyWithChecksum).toUpperCase();
  });
};

/**
 * Validates integrity of identity with checksum.
 *
 * @function verifyChecksum
 * @memberof module:qubic
 * @param {string} identity - Identity in uppercase hex.
 * @returns {Promise<boolean>}
 */
export const verifyChecksum = function (identity) {
  return crypto.then(function ({ K12 }) {
    const buffer = shiftedHexToBytes(identity.toLowerCase());
    const checksum = new Uint8Array(CHECKSUM_LENGTH);
    K12(buffer.subarray(0, PUBLIC_KEY_LENGTH), checksum, CHECKSUM_LENGTH, 0);
    for (let i = 0; i < CHECKSUM_LENGTH; i++) {
      if (checksum[i] !== buffer[PUBLIC_KEY_LENGTH + i]) {
        return false;
      }
    }
    return true;
  });
};

/**
 * @function seedChecksum
 * @memberof module:qubic
 * @param {string} seed - Seed in 55 lowercase latin chars.
 * @returns {Promise<string>} Seed checksum in uppercase hex.
 */
export const seedChecksum = function (seed) {
  const buffer = seedToBytes(seed);
  return crypto.then(function ({ K12 }) {
    const checksum = new Uint8Array(Math.ceil(SEED_CHECKSUM_LENGTH));
    K12(buffer, checksum, Math.ceil(SEED_CHECKSUM_LENGTH), 0);
    return bytesToShiftedHex(checksum)
      .slice(0, HEX_CHARS_PER_BYTE * SEED_CHECKSUM_LENGTH)
      .toUpperCase();
  });
};

// const sA = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc';
// const sB = 'cbazyxwvutsrqponmlkjihgfedcbazyxwvutsrqponmlkjihgfedcba';

// crypto.then(function ({ K12, kex, schnorrq }) {
//   const skA = privateKey(sA, 0, K12);
//   const skB = privateKey(sB, 0, K12);

//   console.log('seed of Alice:', sA);
//   console.log('seed of Bob:', sB);

//   console.log('private key of Alice:', skA);

//   createIdentity(sA, 0).then(function (idA) {
//     console.log('identity of Alice:', idA);

//     const hSkB = new Uint8Array(64);
//     K12(skB, hSkB, 64);
//     const shk = kex.compressedSecretAgreement(hSkB, schnorrq.generatePublicKey(skA));
//     console.log('shared secret:', shk);

//     const hSkA = new Uint8Array(64);
//     K12(skA, hSkA, 64);
//     const shk2 = kex.compressedSecretAgreement(hSkA, schnorrq.generatePublicKey(skB));
//     console.log(shk2);

//     const message = Buffer.from('z'.repeat(135));

//     console.log(
//       'signature of Alice:',
//       schnorrq.sign(skA, schnorrq.generatePublicKey(skA), Uint8Array.from(message))
//     );
//   });
// });
