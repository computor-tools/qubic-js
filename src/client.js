'use strict';

import { createConnection } from './connection.js';
import { createTransfer } from './transfer.js';
import { createIdentity } from './identity.js';
import level from 'level';
import path from 'path';
import bigInt from 'big-integer';

/* globals Connection */

/**
 * @function createClient
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
 * @param {object} [options.db] - Database implementing the [level interface](https://github.com/Level/level), for storing transfers.
 * @param {string} [options.dbPath] - Database path.
 * @fires Connection#info
 * @fires Connection#open
 * @fires Connection#close
 * @fires Connection#error
 * @fires Client#inclusion
 * @fires Client#rejection
 * @returns {Client}
 * @example import { createClient } from 'qubic-js';
 *
 * const client = createClient({
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
export const createClient = function ({
  seed,
  index = 0,
  connection,
  computors,
  synchronizationInterval,
  adminPublicKey,
  reconnectTimeoutDuration,
  db,
  dbPath,
}) {
  connection =
    connection ||
    createConnection({
      computors,
      synchronizationInterval,
      adminPublicKey,
      reconnectTimeoutDuration,
    });
  const identity = createIdentity(seed, index);
  db = Promise.resolve(
    db ||
      identity.then(function (identity) {
        return level(path.join(dbPath || './', identity));
      })
  );
  const infoListeners = [];
  const emittersByEnvironment = new Map();

  const clientMixin = function () {
    const that = this;

    const onTransfer = function (key) {
      const infoListener = async function ({ syncStatus }) {
        if (syncStatus > 2) {
          const response = await connection.sendCommand(4, { hash: key });
          if (response.inclusionState === true) {
            (await db).del(key).then(function () {
              that.removeListener('info', infoListener);
              /**
               * Inclusion event.
               *
               * @event Client#inclusion
               * @type {object}
               * @property {string} hash - Hash of included transfer in uppercase hex.
               * @property {number} epoch - Epoch at which transfer was included.
               * @property {number} tick - Tick at which transfer was included.
               */
              that.emit('inclusion', {
                hash: key,
                inclusionState: true,
                tick: response.tick,
                epoch: response.epoch,
              });
            });
          } else if (response.reason) {
            /**
             * Rejection event.
             *
             * @event Client#rejection
             * @type {object}
             * @property {string} hash - Hash of rejected transfer in uppercase hex.
             * @property {string} reason - Reason of rejection.
             */
            that.emit('rejection', { hash: key, reason: response.reason });
          }
        }
      };
      that.addListener('info', infoListener);
      infoListeners.push(infoListener);
    };

    db.then(function (db) {
      db.on('put', onTransfer);
      db.createKeyStream().on('data', onTransfer);
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
        return identity;
      },

      /**
       * @function createTransfer
       * @memberof Client
       * @param {object} to
       * @param {string} to.identity - Recipient identity in uppercase hex.
       * @param {bigint} to.energy - Transferred energy to recipient identity.
       * @returns {object} Transfer object.
       */
      async createTransfer(to) {
        const [{ identityNonce }, { energy }] = await Promise.all([
          connection.sendCommand(1, { identity: await identity }),
          connection.sendCommand(2, { identity: await identity }),
        ]);

        const transfer = await createTransfer({
          seed,
          from: {
            identity: await identity,
            index,
            identityNonce,
            energy: bigInt(energy),
          },
          to,
        });

        return (await db).put(transfer.hash, JSON.stringify(transfer)).then(function () {
          connection.sendCommand(3, {
            message: transfer.message,
            signature: transfer.signature,
          });
          return transfer;
        });
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
          emitter = connection.sendCommand(5, { hash: environment });
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
          connection.sendCommand(6, { hash: environment });
          emitter.removeListener(environment, listener);
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
        (await db).close();
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
        connection.open();
        (await db).open();
        (await db).on('put', onTransfer);
        (await db).createKeyStream().on('data', onTransfer);
      },
    });
  };

  return clientMixin.call(connection);
};
