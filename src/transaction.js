'use strict';

import bigInt from 'big-integer';
import {
  PUBLIC_KEY_LENGTH,
  PUBLIC_KEY_LENGTH_IN_HEX,
  privateKey,
  verifyChecksum,
} from './identity.js';
import { shiftedHexToBytes, bytesToShiftedHex, hexToBytes } from './utils/hex.js';
import { crypto } from './crypto/index.js';

export const SENDER_IDENTITY_OFFSET = 0;
export const SENDER_IDENTITY_LENGTH = PUBLIC_KEY_LENGTH;
export const IDENTITY_NONCE_OFFSET = SENDER_IDENTITY_OFFSET + SENDER_IDENTITY_LENGTH;
export const IDENTITY_NONCE_LENGTH = 4;
export const ENERGY_OFFSET = IDENTITY_NONCE_OFFSET + IDENTITY_NONCE_LENGTH;
export const ENERGY_LENGTH = 8;
export const RECEIVER_IDENTITY_OFFSET = ENERGY_OFFSET + ENERGY_LENGTH;
export const RECEIVER_IDENTITY_LENGTH = PUBLIC_KEY_LENGTH;
export const EFFECT_PAYLOAD_OFFSET = RECEIVER_IDENTITY_OFFSET + RECEIVER_IDENTITY_LENGTH;

export const HASH_LENGTH = 32; // 256-bit output for 128-bit collision security (see 4.1 of https://eprint.iacr.org/2016/770.pdf).

/**
 * @typedef {object} TransferParams
 * @property {string} seed - Seed in 55 lowercase latin chars.
 * @property {number} index - Index of private key which was used to derive sender identity.
 * @property {string} senderIdentity - Sender identity in uppercase hex.
 * @property {number} identityNonce - Identity nonce.
 * @property {bigint} energy - Transferred energy to recipient identity.
 * @property {string} recipientIdentity - Recipient identity in uppercase hex.
 */

/**
 * @typedef {object} EffectParams
 * @property {string} seed - Seed in 55 lowercase latin chars.
 * @property {number} index - Index of private key which was used to derive sender identity.
 * @property {string} senderIdentity - Sender identity in uppercase hex.
 * @property {number} identityNonce - Identity nonce.
 * @property {Uint8Array} effectPayload - Effect payload
 */

/**
 * @typedef {object} TransferAndEffectParams
 * @property {string} seed - Seed in 55 lowercase latin chars.
 * @property {number} index - Index of private key which was used to derive sender identity.
 * @property {string} senderIdentity - Sender identity in shifted uppercase hex.
 * @property {number} identityNonce - Identity nonce.
 * @property {bigint} energy - Transferred energy to recipient identity.
 * @property {string} recipientIdentity - Recipient identity in shifted uppercase hex.
 * @property {Uint8Array} effectPayload - Effect payload
 */

/**
 * @typedef {object} Transaction
 * @property {string} hash - Transaction hash in shifted uppercase hex.
 * @property {string} message - Base64-encoded signed message.
 * @property {string} signature - Base64-encoded signature.
 */

/**
 * Creates a transaction which includes a transfer of energy between 2 entities,
 * or an effect, or both. Transaction is atomic, meaaning that both transfer and
 * effect will be proccessed or none.
 *
 * @function transaction
 * @memberof module:qubic
 * @param {TransferParams | EffectParams | TransferAndEffectParams} params
 * @returns {Promise<Transaction>}
 * @example import qubic from 'qubic-js';
 *
 * qubic
 *   .transaction({
 *     seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
 *     senderIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
 *     index: 1337,
 *     identityNonce: 0,
 *     recipientIdentity: 'BPFJANADOGBDLNNONDILEMAICAKMEEGBFPJBKPBCEDFJIALDONODMAIMDBFKCFEEMEOLFK',
 *     energy: qubic.energy(1),
 *   })
 *   .then(function (transaction) {
 *     console.log(transaction);
 *   })
 *   .catch(function (error) {
 *     console.log(error.message);
 *   });
 *
 */
export const transaction = async function ({
  seed,
  index,
  senderIdentity,
  identityNonce,
  energy,
  recipientIdentity,
  effectPayload,
}) {
  if ((await verifyChecksum(senderIdentity)) === false) {
    throw new Error(`Invalid checksum: ${senderIdentity}`);
  }

  if (index !== undefined) {
    if (!Number.isInteger(index) || index < 0) {
      throw new Error('Illegal index.');
    }
  }

  if (!Number.isInteger(identityNonce) || identityNonce < 0) {
    throw new Error('Illegal identity nonce.');
  }

  if (recipientIdentity !== undefined) {
    if (!(energy instanceof bigInt) || energy.lesser(bigInt.zero)) {
      throw new Error('Illegal energy.');
    }

    if ((await verifyChecksum(recipientIdentity)) === false) {
      throw new Error(`Invalid checksum: ${recipientIdentity}`);
    }
  }

  if (
    effectPayload !== undefined &&
    (!ArrayBuffer.isView(effectPayload) || effectPayload instanceof DataView)
  ) {
    throw new Error('Illegal effect payload.');
  }

  const message = new Uint8Array(
    SENDER_IDENTITY_LENGTH +
      IDENTITY_NONCE_LENGTH +
      ENERGY_LENGTH +
      RECEIVER_IDENTITY_LENGTH +
      (effectPayload?.byteLength || 0)
  );
  const publicKey = shiftedHexToBytes(
    senderIdentity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()
  );
  message.set(publicKey);
  const buffer = new ArrayBuffer(IDENTITY_NONCE_LENGTH);
  const view = new DataView(buffer);

  view.setUint32(0, identityNonce);
  message.set(Uint8Array.from(buffer), IDENTITY_NONCE_OFFSET);

  if (recipientIdentity !== undefined) {
    message.set(Uint8Array.from(hexToBytes(energy.toString(16))), ENERGY_OFFSET);
    message.set(
      shiftedHexToBytes(recipientIdentity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()),
      RECEIVER_IDENTITY_OFFSET
    );
  }

  if (effectPayload !== undefined) {
    message.set(
      new Uint8Array(effectPayload.buffer, effectPayload.byteOffset, effectPayload.byteLength),
      EFFECT_PAYLOAD_OFFSET
    );
  }

  const { schnorrq, K12 } = await crypto;
  const messageDigest = new Uint8Array(HASH_LENGTH);
  K12(message, messageDigest, HASH_LENGTH);

  const tx = {
    messageDigest: bytesToShiftedHex(messageDigest).toUpperCase(),
    message: Buffer.from(message).toString('base64'),
    signature: Buffer.from(
      schnorrq.sign(privateKey(seed, index || 0, K12), publicKey, messageDigest)
    ).toString('base64'),
  };

  Object.freeze(tx);

  return tx;
};
