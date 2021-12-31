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

export const FROM_IDENTITY_OFFSET = 0;
export const IDENTITY_NONCE_OFFSET = FROM_IDENTITY_OFFSET + PUBLIC_KEY_LENGTH;
export const IDENTITY_NONCE_LENGTH = 4;
export const TO_IDENTITY_OFFSET = IDENTITY_NONCE_OFFSET + IDENTITY_NONCE_LENGTH;
export const ENERGY_OFFSET = TO_IDENTITY_OFFSET + PUBLIC_KEY_LENGTH;
export const HASH_LENGTH = 32;

/**
 * Creates a transfer of energy between 2 entities.
 *
 * @function createTransfer
 * @memberof module:qubic
 * @param {object} params
 * @param {string} params.seed - Seed in 55 lowercase latin chars.
 * @param {object} params.from
 * @param {string} params.from.identity - Sender identity in uppercase hex.
 * @param {number} params.from.index - Index of private key which was used to derive sender identity.
 * @param {number} params.from.identityNonce - Identity nonce.
 * @param {bigint} params.from.enery - Energy of sender identity.
 * @param {object} params.to
 * @param {string} params.to.identity - Recipient identity in uppercase hex.
 * @param {bigint} params.to.energy - Transferred energy to recipient identity.
 * @returns {Promise<object>}
 * @example import { createTransfer } from 'qubic-js';
 *
 * createTransfer({
 *   seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
 *   from: {
 *     identity: '9F6ADD0C591DBB8C0CE1EDF6F63A9E1C7BD22CFBD20DE1469ADAA76A9C0023707BE416',
 *     index: 1337,
 *     identityNonce: 0,
 *     energy: bigInt(2),
 *   },
 *   to: {
 *     identity: 'CD5B4A78521A9F9428F442E60E25DA63247817AB6BBF406CC91393F6664E38CBFE68DC',
 *     energy: bigInt(1),
 *   },
 * })
 *   .then(function (transfer) {
 *     console.log(transfer);
 *   })
 *   .catch(function (error) {
 *     console.log(error.message);
 *   });
 *
 */
export const createTransfer = async function ({ seed, from, to }) {
  if ((await verifyChecksum(from.identity)) === false) {
    throw new Error(`Invalid checksum: ${from.identity}`);
  }
  if ((await verifyChecksum(to.identity)) === false) {
    throw new Error(`Invalid checksum: ${to.identity}`);
  }

  if (!Number.isInteger(from.index) || from.index < 0) {
    throw new Error('Illegal index.');
  }

  if (!Number.isInteger(from.identityNonce)) {
    throw new Error('Illegal nonce.');
  }

  if (
    (from.energy !== undefined && !(from.energy instanceof bigInt)) ||
    !(to.energy instanceof bigInt)
  ) {
    throw new Error('Illegal energy.');
  }

  if (from.energy !== undefined && from.energy.minus(to.energy).lesser(bigInt.zero)) {
    throw new Error('Insufficient energy.');
  }

  const energyBytes = Uint8Array.from(hexToBytes(to.energy.toString(16)));
  const message = new Uint8Array(
    PUBLIC_KEY_LENGTH * 2 + IDENTITY_NONCE_LENGTH + energyBytes.length
  );
  const publicKey = shiftedHexToBytes(
    from.identity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()
  );
  message.set(publicKey);
  const buffer = new ArrayBuffer(IDENTITY_NONCE_LENGTH);
  const view = new DataView(buffer);
  view.setUint32(0, from.identityNonce);
  message.set(Uint8Array.from(buffer), IDENTITY_NONCE_OFFSET);
  message.set(
    shiftedHexToBytes(to.identity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()),
    TO_IDENTITY_OFFSET
  );
  message.set(energyBytes, ENERGY_OFFSET);

  const { schnorrq, K12 } = await crypto;
  const hash = new Uint8Array(HASH_LENGTH);
  K12(message, hash, HASH_LENGTH);
  return {
    hash: bytesToShiftedHex(hash).toUpperCase(),
    message: Buffer.from(message).toString('base64'),
    signature: Buffer.from(
      schnorrq.sign(privateKey(seed, from.index, K12), publicKey, message)
    ).toString('base64'),
  };
};
