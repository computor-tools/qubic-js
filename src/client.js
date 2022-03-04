'use strict';

import { connection as _connection } from './connection.js';
import { HASH_LENGTH, SIGNATURE_OFFSET, transfer, transferObject } from './transfer.js';
import { seedToBytes, identity, privateKey } from './identity.js';
import { crypto } from './crypto/index.js';
import level from 'level';
import path from 'path';
import aesjs from 'aes-js';
import { bytesToShiftedHex } from './utils/hex.js';

/* globals Connection */

/**
 * @function client
 * @memberof module:qubic
 * @param {object} options - Client options.
 * @param {string} options.seed - Seed in 55 lowercase latin chars.
 * @param {number} [options.index=0] - Identity index.
 * @param {Connection} [options.connection] - Client connection.
 * @param {object[]} [options.computors] - Specifies 3 computors to connect to, and with what options.
 * Ignored when connection option is used.
 * @param {string} options.computors[].url - Computor url.
 * @param {object} [options.computors[].options] - WebSocket options.
 * @param {number} [options.synchronizationInterval] - If no new tick appears after this interval an info event is emitted with updated sync status.
 * Ignored when connection option is used.
 * @param {string} [options.adminPublicKey] - Admin public key, for verification of current epoch and tick which are signed by admin.
 * Ignored when connection option is used.
 * @param {number} [options.reconnectTimeoutDuration=100] - Reconnect timeout duration. Ignored when connection option is used.
 * @param options.database
 * @param options.databasePath
 * @param {object} [options.db] - Database implementing the [level interface](https://github.com/Level/level), for storing transactions.
 * @param {string} [options.dbPath] - Database path.
 * @fires Connection#info
 * @fires Connection#open
 * @fires Connection#close
 * @fires Connection#error
 * @fires Client#inclusion
 * @fires Client#rejection
 * @returns {Client}
 * @example import qubic from 'qubic-js';
 *
 * const client = qubic.client({
 *   seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
 *   computors: [
 *     { url: 'wss://AA.computor.com' },
 *     { url: 'wss://AB.computor.com' },
 *     { url: 'wss://AC.computor.com' },
 *   ],
 *   synchronizationInterval: 60 * 1000,
 *   adminPublicKey: '97CC65D1E59351EEFC776BCFF197533F148A8105DA84129C051F70DD9CA0FF82',
 * });
 *
 * client.addListener('error', function (error) {
 *   console.log(error.message);
 * });
 * client.addListener('info', console.log);
 *
 */
export const client = function ({
  seed,
  index = 0,
  connection,
  computors,
  synchronizationInterval,
  adminPublicKey,
  reconnectTimeoutDuration,
  database,
  databasePath,
}) {
  connection =
    connection ||
    _connection({
      computors,
      synchronizationInterval,
      adminPublicKey,
      reconnectTimeoutDuration,
    });
  const id = identity(seed, index);
  database = Promise.resolve(
    database ||
      id.then(function (id) {
        return level(path.join(databasePath || './', id));
      })
  );
  const infoListeners = [];
  const emittersByEnvironment = new Map();

  const clientMixin = function () {
    const that = this;

    const hashesByIndex = new Map();
    const transfers = [];
    let counter = 0;
    let resolveAESCounter;
    let AESCounter = new Promise(function (resolve) {
      resolveAESCounter = resolve;
    });
    let energy = 0n;
    let databaseSignature;

    const databaseEssence = function () {
      const essence = new Uint8Array(4 + 8 + hashesByIndex.size * HASH_LENGTH);
      const essenceView = new DataView(essence.buffer);
      essenceView.setUint32(0, counter, true);
      essenceView.setBigUint64(4, energy, true);
      let offset = 4 + 8;
      hashesByIndex.forEach(function (hash) {
        essence.set(hash, offset);
        offset += HASH_LENGTH;
      });
      return essence;
    };

    const onData = async function (data) {
      switch (data.key) {
        case 'counter':
          counter = new DataView(Uint8Array.from(data.value).buffer).getUint32(0, true);
          break;
        case 'energy':
          energy = new DataView(Uint8Array.from(data.value).buffer).getBigUint64(0, true);
          break;
        case 'signature':
          databaseSignature = Array.from(data.value);
          break;
        default: {
          const { K12, schnorrq } = await crypto;
          const key = new Uint8Array(16);
          K12(seedToBytes(seed), key, 16);
          const aes = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(parseInt(data.key)));
          const signedValue = aes.decrypt(Array.from(data.value));

          switch (signedValue[0]) {
            case 0:
              {
                // unprocessed  transfer
                const value = signedValue.slice(1, 1 + SIGNATURE_OFFSET);
                value[0] = value[0] ^ 1;
                const hash = new Uint8Array(HASH_LENGTH);
                K12(value, hash, HASH_LENGTH);
                if (
                  schnorrq.verify(
                    schnorrq.generatePublicKey(privateKey(seed, index, K12)),
                    hash,
                    signedValue.slice(1 + SIGNATURE_OFFSET)
                  ) === 1
                ) {
                  hashesByIndex.set(parseInt(data.key), hash);
                  transfers.push(await transferObject(signedValue.slice(1), hash));
                  let latestRequestTimestamp = Date.now();
                  const infoListener = async function ({ computerState }) {
                    if (computerState.status >= 2 && Date.now() - latestRequestTimestamp > 10000) {
                      latestRequestTimestamp = Date.now();
                      console.log('GET_TRANSFER_STATUS');
                      connection.getTransferStatus(bytesToShiftedHex(hash).toUpperCase());
                    }
                  };
                  connection.addListener('info', infoListener);
                  infoListeners.push(infoListener);
                }
              }
              break;
            case 2: {
              // processed transfer
              const value = signedValue.slice(1, 1 + SIGNATURE_OFFSET);
              value[0] = value[0] ^ 1;
              const hash = new Uint8Array(HASH_LENGTH);
              K12(value, hash, HASH_LENGTH);
              if (
                schnorrq.verify(
                  schnorrq.generatePublicKey(privateKey(seed, index, K12)),
                  hash,
                  signedValue.slice(1 + SIGNATURE_OFFSET)
                ) === 1
              ) {
                hashesByIndex.set(parseInt(data.key), hash);
                transfers.push(await transferObject(signedValue.slice(1), hash));
              }
            }
          }
        }
      }
    };

    const onEnd = async function () {
      if (counter === 0) {
        resolveAESCounter();
      }

      if (hashesByIndex.size > 0 || energy > 0n || counter > 0) {
        const { schnorrq, K12 } = await crypto;
        if (
          schnorrq.verify(
            schnorrq.generatePublicKey(privateKey(seed, index, K12)),
            databaseEssence(),
            databaseSignature
          ) === 1
        ) {
          resolveAESCounter();
          that.emit('energy', energy);
          transfers.forEach(function (transfer) {
            that.emit('transfer', transfer);
          });
        }
      }
    };

    let stream;
    database.then(function (database) {
      stream = database
        .createReadStream({ valueEncoding: 'binary' })
        .on('data', onData)
        .on('end', onEnd);
    });

    /**
     * @mixin Client
     * @mixes Connection
     */
    return Object.assign(this, {
      /**
       * @type {string} Client identity in uppercase hex.
       * @memberof Client
       */
      get identity() {
        return id;
      },

      /* eslint-disable jsdoc/no-undefined-types */
      /**
       * Creates a transaction which includes a transfer of energy between 2 entities,
       * or an effect, or both. Transaction is atomic, meaaning that both transfer and
       * effect will be proccessed or none.
       *
       * Transactions are stored in database and their inclusion or rejection are monitored.
       *
       * @function transfer
       * @memberof Client
       * @param {object} params
       * @param {string} [params.destination] - Destination identity in uppercase hex.
       * @param {bigint} [params.energy] - Transferred energy to recipient identity.
       * @returns {Transaction} Transaction object.
       */
      /* eslint-enable jsdoc/no-undefined-types */
      async transfer(params) {
        if (energy < BigInt(params.energy)) {
          throw new Error('Insufficient energy.');
        }

        const transferObject = await transfer({
          seed,
          index,
          source: await id,
          destination: params.destination,
          energy: params.energy,
        });
        const { hashBytes, bytes } = transferObject;

        await AESCounter;
        counter++;
        hashesByIndex.set(counter, hashBytes);
        const essence = databaseEssence();
        const { K12, schnorrq } = await crypto;
        const secretKey = privateKey(seed, index, K12);
        const signature = schnorrq.sign(secretKey, schnorrq.generatePublicKey(secretKey), essence);
        const key = new Uint8Array(16);
        K12(seedToBytes(seed), key, 16);

        const aes = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(counter));

        const counterBytes = new Uint8Array(4);
        const counterView = new DataView(counterBytes.buffer);
        counterView.setUint32(0, counter, true);

        const bytesCopy = new Uint8Array(1 + bytes.length);
        bytesCopy[0] = 0;
        bytesCopy.set(bytes, 1);

        await (
          await database
        )
          .batch()
          .put('counter', Buffer.from(counterBytes), { valueEncoding: 'binary' })
          .put('signature', Buffer.from(signature), { valueEncoding: 'binary' })
          .put(counter, Buffer.from(aes.encrypt(bytesCopy)), { valueEncoding: 'binary' })
          .write();

        that.emit('transfer', transferObject);

        connection.broadcastTransfer(bytes);
      },

      /**
       * Subcribes to an environment.
       *
       * @function addEnvironmentListener
       * @memberof Client
       * @param {string} environment - Environment hash.
       * @param {Function} listener
       *
       * @example const listener = function (data) {
       *   console.log(data);
       * };
       *
       * client.addEvironmentListener(
       *   'BPFJANADOGBDLNNONDILEMAICAKMEEGBFPJBKPBCEDFJIALDONODMAIMDBFKCFEE',
       *   listener
       * );
       *
       */
      addEnvironmentListener(environment, listener) {
        let emitter = emittersByEnvironment.get(environment);
        if (emitter === undefined) {
          emitter = connection.sendCommand(5, { environmentDigest: environment });
          emittersByEnvironment.set(environment, emitter);
        }
        emitter.addListener('data', listener);
      },

      /**
       * Unsubscribes from an environment.
       *
       * @function removeEnvironmentListener
       * @memberof Client
       * @param {string} environment - Environment hash.
       * @param {Function} listener
       */
      removeEnvironmentListener(environment, listener) {
        let emitter = emittersByEnvironment.get(environment);
        if (emitter !== undefined) {
          connection.sendCommand(6, { environmentDigest: environment });
          emitter.removeListener('data', listener);
          emittersByEnvironment.delete(environment);
        }
      },

      /**
       * Closes database and connections to computors.
       *
       * @function terminate
       * @memberof Client
       * @param {object} [options]
       * @param {boolean} [options.closeConnection = true]
       */
      async terminate({ closeConnection } = { closeConnection: true }) {
        if (closeConnection) {
          connection.close();
        }
        stream?.destroy();
        (await database).close();
        for (const listener of infoListeners) {
          connection.removeListener('info', listener);
        }
      },

      /**
       * Launches client by opening database and connections to computors.
       *
       * @function launch
       * @memberof Client
       * @fires Connection#info
       * @fires Connection#open
       * @fires Connection#close
       * @fires Connection#error
       * @fires Client#inclusion
       * @fires Client#rejection
       */
      async launch() {
        AESCounter = new Promise(function (resolve) {
          resolveAESCounter = resolve;
        });
        connection.open();
        await (await database).open();
        stream = (await database)
          .createReadStream({ valueEncoding: 'binary' })
          .on('data', onData)
          .on('end', onEnd);
      },

      async setEnergy(value) {
        const energyBytes = new Uint8Array(8);
        const energyView = new DataView(energyBytes.buffer);
        energyView.setBigUint64(0, value, true);
        const energyCopy = energy;
        energy = value;
        const essence = databaseEssence();
        const { K12, schnorrq } = await crypto;
        const secretKey = privateKey(seed, index, K12);
        const signature = schnorrq.sign(secretKey, schnorrq.generatePublicKey(secretKey), essence);
        try {
          (await database)
            .batch()
            .put('energy', Buffer.from(energyBytes), { valueEncoding: 'binary' })
            .put('signature', Buffer.from(signature), { valueEncoding: 'binary' })
            .write();

          that.emit('energy', value);
        } catch {
          energy = energyCopy;
        }
      },
    });
  };

  return clientMixin.call(connection);
};
