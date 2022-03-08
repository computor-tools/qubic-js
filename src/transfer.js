'use strict';

import {
  PUBLIC_KEY_LENGTH,
  PUBLIC_KEY_LENGTH_IN_HEX,
  privateKey,
  verifyChecksum,
  addChecksum,
} from './identity.js';
import { shiftedHexToBytes, bytesToShiftedHex } from './utils/hex.js';
import { crypto } from './crypto/index.js';
import { timestamp } from './timestamp.js';

export const SOURCE_OFFSET = 0;
export const SOURCE_LENGTH = PUBLIC_KEY_LENGTH;
export const DESTINATION_OFFSET = SOURCE_OFFSET + SOURCE_LENGTH;
export const DESTINATION_LENGTH = PUBLIC_KEY_LENGTH;
export const TIMESTAMP_OFFSET = DESTINATION_OFFSET + DESTINATION_LENGTH;
export const TIMESTAMP_LENGTH = 8;
export const ENERGY_OFFSET = TIMESTAMP_OFFSET + TIMESTAMP_LENGTH;
export const ENERGY_LENGTH = 8;
export const SIGNATURE_OFFSET = ENERGY_OFFSET + ENERGY_LENGTH;
export const SIGNATURE_LENGTH = 64;

export const TRANSFER_LENGTH = SIGNATURE_OFFSET + SIGNATURE_LENGTH;

export const HASH_LENGTH = 32; // 256-bit output for 128-bit collision security (see 4.1 of https://eprint.iacr.org/2016/770.pdf).

export const MIN_ENERGY_AMOUNT = 1000000n;

/**
 * @typedef {object} TransferParams
 * @property {string} seed - Seed in 55 lowercase latin chars.
 * @property {number} index - Index of private key which was used to derive sender identity.
 * @property {string} sourceIdentity - Source identity in uppercase hex.
 * @property {string} destinationIdentity - Destination identity in uppercase hex.
 * @property {bigint} energy - Transferred energy to recipient identity.
 */

/**
 * Creates a transaction which includes a transfer of energy between 2 entities,
 * or an effect, or both. Transaction is atomic, meaaning that both transfer and
 * effect will be proccessed or none.
 *
 * @function transfer
 * @memberof module:qubic
 * @param {TransferParams} params
 * @returns {Promise<object>}
 * @example import qubic from 'qubic-js';
 *
 * qubic
 *   .transaction({
 *     seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
 *     index: 1337,
 *     sourceIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
 *     destinationIdentity: 'BPFJANADOGBDLNNONDILEMAICAKMEEGBFPJBKPBCEDFJIALDONODMAIMDBFKCFEEMEOLFK',
 *     identityNonce: 0,
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
export const transfer = async function ({ seed, index, source, destination, energy }) {
  if ((await verifyChecksum(source)) === false) {
    throw new Error(`Invalid checksum: ${source}`);
  }

  if (index !== undefined) {
    if (!Number.isInteger(index) || index < 0) {
      throw new Error('Illegal index.');
    }
  }

  if ((await verifyChecksum(destination)) === false) {
    throw new Error(`Invalid checksum: ${destination}`);
  }
  if (BigInt(energy) < MIN_ENERGY_AMOUNT) {
    throw new Error('Illegal energy.');
  }

  const transferAndSignature = new Uint8Array(
    SOURCE_LENGTH + DESTINATION_LENGTH + TIMESTAMP_LENGTH + ENERGY_LENGTH + SIGNATURE_LENGTH
  );
  const transferAndSignatureView = new DataView(transferAndSignature.buffer);

  const publicKey = shiftedHexToBytes(source.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase());
  transferAndSignature.set(publicKey, SOURCE_OFFSET);

  transferAndSignature.set(
    shiftedHexToBytes(destination.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()),
    DESTINATION_OFFSET
  );

  const ts = timestamp();
  transferAndSignatureView.setBigUint64(TIMESTAMP_OFFSET, ts, true);

  transferAndSignatureView.setBigUint64(ENERGY_OFFSET, BigInt(energy), true);

  const { schnorrq, K12 } = await crypto;
  const digest = new Uint8Array(HASH_LENGTH);
  transferAndSignature[0] ^= 1;
  K12(transferAndSignature.subarray(SOURCE_OFFSET, SIGNATURE_OFFSET), digest, HASH_LENGTH);
  transferAndSignature[0] ^= 1;
  const signature = schnorrq.sign(privateKey(seed, index || 0, K12), publicKey, digest);
  transferAndSignature.set(signature, SIGNATURE_OFFSET);

  const hashBytes = new Uint8Array(HASH_LENGTH);
  K12(transferAndSignature, hashBytes, HASH_LENGTH);

  const transferObj = {
    bytes: transferAndSignature,
    hashBytes,
    hash: bytesToShiftedHex(hashBytes).toUpperCase(),
    source,
    destination,
    timestamp: ts,
    energy: BigInt(energy),
    signature: Buffer.from(signature).toString('base64'),
  };

  Object.freeze(transferObj);

  return transferObj;
};

export const transferObject = async function (transfer, hashBytes) {
  const transferView = new DataView(transfer.buffer);

  if (hashBytes === undefined) {
    hashBytes = new Uint8Array(HASH_LENGTH);
    (await crypto).K12(transfer.slice(), hashBytes, HASH_LENGTH);
  }

  const transferObj = {
    bytes: transfer.slice(),
    hashBytes,
    hash: bytesToShiftedHex(hashBytes).toUpperCase(),
    source: bytesToShiftedHex(
      await addChecksum(transfer.subarray(SOURCE_OFFSET, SOURCE_OFFSET + SOURCE_LENGTH))
    ).toUpperCase(),
    destination: bytesToShiftedHex(
      await addChecksum(
        transfer.subarray(DESTINATION_OFFSET, DESTINATION_OFFSET + DESTINATION_LENGTH)
      )
    ).toUpperCase(),
    timestamp: transferView.getBigUint64(TIMESTAMP_OFFSET, true),
    energy: transferView.getBigUint64(ENERGY_OFFSET, true),
    signature: Buffer.from(
      transfer.subarray(SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH)
    ).toString('base64'),
  };

  Object.freeze(transferObj);

  return transferObj;
};
