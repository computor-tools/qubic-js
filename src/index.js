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
import { transaction } from './transaction.js';
import { connection } from './connection.js';
import { client } from './client.js';
import { crypto } from './crypto/index.js';

/**
 * @module qubic
 */
const qubic = {
  identity,
  verifyChecksum,
  privateKey,
  seedChecksum,
  SEED_IN_LOWERCASE_LATIN_LENGTH,
  CHECKSUM_LENGTH,
  PUBLIC_KEY_LENGTH,
  PUBLIC_KEY_LENGTH_IN_HEX,
  transaction,
  connection,
  client,
  crypto,
};

export default qubic;
