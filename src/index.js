'use strict';

import {
  identity,
  verifyChecksum,
  privateKey,
  seedChecksum,
  SEED_IN_LOWERCASE_LATIN_LENGTH,
  CHECKSUM_LENGTH,
  PUBLIC_KEY_LENGTH,
  PUBLIC_KEY_LENGTH_IN_HEX,
} from './identity.js';
import { transfer } from './transfer.js';
import { connection } from './connection.js';
import { client } from './client.js';
import { computor } from './computor.js';
import { crypto } from './crypto/index.js';
import { shiftedHexToBytes } from './utils/hex.js';

/**
 * @module qubic
 */
const qubic = {
  identity,
  verifyChecksum,
  privateKey,
  seedChecksum,
  transfer,
  connection,
  client,
  computor,
  crypto,
  shiftedHexToBytes
};

export default qubic;

export {
  SEED_IN_LOWERCASE_LATIN_LENGTH,
  CHECKSUM_LENGTH,
  PUBLIC_KEY_LENGTH,
  PUBLIC_KEY_LENGTH_IN_HEX,
};
