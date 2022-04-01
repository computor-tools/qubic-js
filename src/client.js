'use strict';

import {
  COMPUTER_STATE_COMPUTOR_INDEX_OFFSET,
  COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET,
  COMPUTER_STATE_SIGNATURE_LENGTH,
  COMPUTER_STATE_SIGNATURE_OFFSET,
  connection as _connection,
  NUMBER_OF_COMPUTORS,
  TRANSFER_STATUS_COMPUTOR_INDEX_LENGTH,
  TRANSFER_STATUS_COMPUTOR_INDEX_OFFSET,
  TRANSFER_STATUS_DIGEST_OFFSET,
  TRANSFER_STATUS_SIGNATURE_LENGTH,
  TRANSFER_STATUS_SIGNATURE_OFFSET,
  TRANSFER_STATUS_STATUS_LENGTH,
  TRANSFER_STATUS_STATUS_OFFSET,
} from './connection.js';
import {
  HASH_LENGTH,
  SIGNATURE_OFFSET,
  transfer,
  transferObject,
  TRANSFER_LENGTH,
  SIGNATURE_LENGTH,
  SOURCE_LENGTH,
  SOURCE_OFFSET,
} from './transfer.js';
import { seedToBytes, identity, privateKey, PUBLIC_KEY_LENGTH } from './identity.js';
import { timestamp } from './timestamp.js';
import { crypto } from './crypto/index.js';
import level from 'level';
import path from 'path';
import aesjs from 'aes-js';
import { bytesToShiftedHex, shiftedHexToBytes } from './utils/hex.js';

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

  const adminPublicKeyBytes = shiftedHexToBytes(adminPublicKey.toLowerCase());
  let isAdminPublicKeyNULL = true;
  for (let i = 0; i < adminPublicKeyBytes.length; i++) {
    if (adminPublicKeyBytes[i] !== 0) {
      isAdminPublicKeyNULL = false;
      break;
    }
  }
  if (isAdminPublicKeyNULL) {
    throw new Error('Illegal admin public key.');
  }

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

    const hashes = new Set();
    const hashesByIndex = new Map();
    const transfers = new Set();
    const transferStatuses = [];
    const receipts = [];
    let counter = 0;
    let latestUnprocessedTransaction = { index: -1, decryptedValue: [], timestamp: 0n };
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
      Array.from(hashesByIndex.values())
        .sort()
        .forEach(function (hash) {
          essence.set(hash, offset);
          offset += HASH_LENGTH;
        });
      return essence;
    };

    const processTransferStatus = function (params) {
      let latestRequestTimestamp = Date.now() - NUMBER_OF_COMPUTORS * 100 * 2;
      let receivedReceipt = false;

      const infoListener = async function ({ computerState }) {
        if (
          computerState.status >= 2 &&
          Date.now() - latestRequestTimestamp > NUMBER_OF_COMPUTORS * 100 * 2
        ) {
          latestRequestTimestamp = Date.now();
          if (receivedReceipt === false) {
            const response = await connection.getTransferStatus(params.hash);

            if (
              response.receipt !== undefined &&
              receivedReceipt === false &&
              (receivedReceipt = true)
            ) {
              const { K12, schnorrq } = await crypto;

              await AESCounter;
              const counterValue = ++counter;
              hashesByIndex.delete(params.counter);
              hashesByIndex.set(counterValue, params.hashBytes);
              const energyCopy = energy;
              energy = (await id) === params.destination ? energy : energy - params.energy;
              if (energy < 0n) {
                energy = 0n;
              }
              const essence = databaseEssence();
              const secretKey = privateKey(seed, index, K12);
              const signature = schnorrq.sign(
                secretKey,
                schnorrq.generatePublicKey(secretKey),
                essence
              );

              const counterBytes = new Uint8Array(4);
              const counterView = new DataView(counterBytes.buffer);
              counterView.setUint32(0, counterValue, true);
              const energyBytes = new Uint8Array(8);
              const energyView = new DataView(energyBytes.buffer);
              energyView.setBigUint64(0, energy, true);
              const transferAndReceipt = new Uint8Array(
                1 + params.transfer.length + response.receipt.length
              );
              transferAndReceipt[0] = 1;
              transferAndReceipt.set(params.transfer, 1);
              transferAndReceipt.set(response.receipt, 1 + params.transfer.length);

              const key = new Uint8Array(16);
              K12(seedToBytes(seed), key, 16);

              const aes = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(counterValue));

              try {
                await (
                  await database
                )
                  .batch()
                  .del(params.counter, { valueEncoding: 'binary' })
                  .put(counterValue, Buffer.from(aes.encrypt(transferAndReceipt)), {
                    valueEncoding: 'binary',
                  })
                  .put('counter', Buffer.from(counterBytes), {
                    valueEncoding: 'binary',
                  })
                  .put('energy', Buffer.from(energyBytes), {
                    valueEncoding: 'binary',
                  })
                  .put('signature', Buffer.from(signature), {
                    valueEncoding: 'binary',
                  })
                  .write();

                connection.removeListener('info', infoListener);

                that.emit('energy', energy);

                that.emit('receipt', {
                  ...response,
                  receipt: transferAndReceipt.slice(1),
                  receiptBase64: Buffer.from(transferAndReceipt.slice(1)).toString('base64'),
                });
              } catch {
                receivedReceipt = false;
                energy = energyCopy;
              }
            }
          }
        }
      };

      connection.addListener('info', infoListener);
      infoListeners.push(infoListener);
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
          const decryptedValue = aes.decrypt(Array.from(data.value));
          switch (decryptedValue[0]) {
            case 0:
              {
                // unprocessed  transfer
                const digest = new Uint8Array(HASH_LENGTH);
                const message = decryptedValue.subarray(1, 1 + SIGNATURE_OFFSET);
                message[0] ^= 1;
                K12(message, digest, HASH_LENGTH);
                message[0] ^= 1;
                if (
                  schnorrq.verify(
                    schnorrq.generatePublicKey(privateKey(seed, index, K12)),
                    digest,
                    decryptedValue.subarray(1 + SIGNATURE_OFFSET)
                  ) === 1
                ) {
                  const hashBytes = new Uint8Array(HASH_LENGTH);
                  const bytes = decryptedValue.slice(1);
                  K12(bytes, hashBytes, HASH_LENGTH);
                  hashesByIndex.set(parseInt(data.key), hashBytes);
                  const transfer = await transferObject(bytes, hashBytes);

                  if (latestUnprocessedTransaction.index < parseInt(data.key)) {
                    latestUnprocessedTransaction.index = parseInt(data.key);
                    latestUnprocessedTransaction.decryptedValue = decryptedValue.slice(1);
                    latestUnprocessedTransaction.timestamp = transfer.timestamp;
                  }
                  transfers.add(transfer);
                  const hash = bytesToShiftedHex(hashBytes).toUpperCase();
                  hashes.add(hash);
                  processTransferStatus({
                    hash,
                    hashBytes,
                    transfer: bytes,
                    destination: transfer.destination,
                    energy: transfer.energy,
                    counter: parseInt(data.key),
                  });
                } else {
                  console.error(`Unprocessed tx db sig failed!`);
                }
              }
              break;
            case 1: {
              // processed transfer
              const decryptedValueView = new DataView(decryptedValue.buffer);
              const digest = new Uint8Array(HASH_LENGTH);
              const message = decryptedValue.subarray(1, 1 + SIGNATURE_OFFSET);
              message[0] ^= 1;
              K12(message, digest, HASH_LENGTH);
              message[0] ^= 1;
              let offset = 1 + SIGNATURE_OFFSET;
              if (
                schnorrq.verify(
                  decryptedValue.subarray(1 + SOURCE_OFFSET, 1 + SOURCE_OFFSET + SOURCE_LENGTH),
                  digest,
                  decryptedValue.subarray(offset, (offset += SIGNATURE_LENGTH))
                ) === 1
              ) {
                const computerStateDigest = new Uint8Array(HASH_LENGTH);
                K12(
                  decryptedValue.subarray(
                    offset,
                    (offset +=
                      COMPUTER_STATE_SIGNATURE_OFFSET - COMPUTER_STATE_COMPUTOR_INDEX_OFFSET)
                  ),
                  computerStateDigest,
                  HASH_LENGTH
                );
                if (
                  schnorrq.verify(
                    adminPublicKeyBytes,
                    computerStateDigest,
                    decryptedValue.slice(offset, (offset += COMPUTER_STATE_SIGNATURE_LENGTH))
                  ) === 1
                ) {
                  const computorPublicKeys = [];
                  let computorPublicKeysOffset =
                    1 +
                    TRANSFER_LENGTH +
                    COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET -
                    COMPUTER_STATE_COMPUTOR_INDEX_OFFSET;
                  for (let i = 0; i < NUMBER_OF_COMPUTORS; i++) {
                    computorPublicKeys.push(
                      decryptedValue.subarray(
                        computorPublicKeysOffset + i * PUBLIC_KEY_LENGTH,
                        computorPublicKeysOffset + (i + 1) * PUBLIC_KEY_LENGTH
                      )
                    );
                  }

                  const statuses = [];

                  while (offset < decryptedValue.length) {
                    const transferStatusOffset =
                      offset + TRANSFER_STATUS_STATUS_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET;
                    const digest = new Uint8Array(HASH_LENGTH);
                    decryptedValue[offset] ^= 3;
                    K12(
                      decryptedValue.subarray(
                        offset,
                        (offset += TRANSFER_STATUS_SIGNATURE_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET)
                      ),
                      digest,
                      HASH_LENGTH
                    );
                    decryptedValue[
                      offset - (TRANSFER_STATUS_SIGNATURE_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET)
                    ] ^= 3;
                    const computorIndex = decryptedValueView[
                      'getUint' + TRANSFER_STATUS_COMPUTOR_INDEX_LENGTH * 8
                    ](
                      offset -
                        (TRANSFER_STATUS_SIGNATURE_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET) +
                        TRANSFER_STATUS_COMPUTOR_INDEX_OFFSET -
                        TRANSFER_STATUS_DIGEST_OFFSET,
                      true
                    );
                    if (
                      schnorrq.verify(
                        computorPublicKeys[computorIndex],
                        digest,
                        decryptedValue.subarray(
                          offset,
                          (offset += TRANSFER_STATUS_SIGNATURE_LENGTH)
                        )
                      ) === 1
                    ) {
                      if (statuses[computorIndex] === undefined) {
                        statuses[computorIndex] = [];
                      }
                      for (let i = 0; i < TRANSFER_STATUS_STATUS_LENGTH; i++) {
                        for (let j = 0; j < 8; j += 2) {
                          let transferStatus = 0; // unseen
                          if (
                            ((decryptedValue[transferStatusOffset + i] >> (8 - (j + 1))) &
                              0x0001) ===
                            0
                          ) {
                            if (
                              ((decryptedValue[transferStatusOffset + i] >> (8 - (j + 2))) &
                                0x0001) ===
                              1
                            ) {
                              // 01 - seen
                              transferStatus = 1;
                            }
                          } else if (
                            ((decryptedValue[transferStatusOffset + i] >> (8 - (j + 2))) &
                              0x0001) ===
                            0
                          ) {
                            // 10 - processed
                            transferStatus = 2;
                          }
                          statuses[computorIndex][i * 4 + j / 2] = transferStatus;
                        }
                      }
                    }
                  }

                  const report = [0, 0, 0, 0];

                  for (let i = 0; i < NUMBER_OF_COMPUTORS; i++) {
                    for (let j = 0; j < NUMBER_OF_COMPUTORS; j++) {
                      if (i !== j) {
                        if (statuses[i] === undefined || statuses[i][j] === undefined) {
                          report[3] += 1;
                        } else {
                          report[statuses[i][j]] += 1;
                        }
                      }
                    }
                  }

                  const hashBytes = new Uint8Array(HASH_LENGTH);
                  const bytes = decryptedValue.slice(1, 1 + TRANSFER_LENGTH);
                  K12(bytes, hashBytes, HASH_LENGTH);

                  hashesByIndex.set(parseInt(data.key), hashBytes);

                  transfers.add(await transferObject(bytes, hashBytes));
                  const hash = bytesToShiftedHex(hashBytes).toUpperCase();
                  hashes.add(hash);

                  transferStatuses.push({
                    hash,
                    unseen: Math.floor((report[3] + report[0]) / (NUMBER_OF_COMPUTORS - 1)),
                    seen: Math.floor(report[1] / (NUMBER_OF_COMPUTORS - 1)),
                    processed: Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)),
                    // TODO: add epoch/tick
                  });

                  receipts.push({
                    hash,
                    receipt: decryptedValue.slice(1),
                    receiptBase64: Buffer.from(decryptedValue.slice(1)).toString('base64'),
                  });
                }
              } else {
                console.error(`Processed Transfer DB Sig failed Verification! ${data.key}`);
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
          let txferDataMap = {};
          transfers.forEach(function (transfer) {
            let key = `${transfer.destination}-${transfer.energy}-${transfer.timestamp}`;
            if (txferDataMap.hasOwnProperty(key)) {
              console.log(`Deleting duplicate transfer before send to UI: ${transfer.hash}`);
              transfers.delete(transfer);
            } else {
              txferDataMap[key] = true;
            }
          });
          transfers.forEach(function (transfer) {
            that.emit('transfer', transfer);
          });

          if (latestUnprocessedTransaction.index > -1) {
            let ts = timestamp();
            let secsElapsedSinceLastTx =
              (ts - latestUnprocessedTransaction.timestamp) / BigInt(1000000000);
            if (secsElapsedSinceLastTx >= 60) {
              console.log('rebroadcasting latest tx');
              connection.broadcastTransfer(latestUnprocessedTransaction.decryptedValue);
              latestUnprocessedTransaction.index = -1;
              latestUnprocessedTransaction.decryptedValue = [];
            }
          }

          transferStatuses.forEach(function (status) {
            that.emit('transferStatus', status);
          });
          receipts.forEach(function (receipt) {
            that.emit('receipt', receipt);
          });
        } else {
          // TODO: emit error if signature is invalid.
          console.log('db sig failed');
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
        const { hashBytes, hash, bytes } = transferObject;

        await AESCounter;
        let counterValue = ++counter;
        hashesByIndex.set(counterValue, hashBytes);
        const essence = databaseEssence();
        const { K12, schnorrq } = await crypto;
        const secretKey = privateKey(seed, index, K12);
        const signature = schnorrq.sign(secretKey, schnorrq.generatePublicKey(secretKey), essence);
        const key = new Uint8Array(16);
        K12(seedToBytes(seed), key, 16);

        const aes = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(counterValue));

        const counterBytes = new Uint8Array(4);
        const counterView = new DataView(counterBytes.buffer);
        counterView.setUint32(0, counterValue, true);

        const bytesCopy = new Uint8Array(1 + bytes.length);
        bytesCopy[0] = 0;
        bytesCopy.set(bytes, 1);

        await (
          await database
        )
          .batch()
          .put('counter', Buffer.from(counterBytes), { valueEncoding: 'binary' })
          .put('signature', Buffer.from(signature), { valueEncoding: 'binary' })
          .put(counterValue, Buffer.from(aes.encrypt(bytesCopy)), { valueEncoding: 'binary' })
          .write();

        hashes.add(hash);

        that.emit('transfer', transferObject);

        connection.broadcastTransfer(bytes);

        processTransferStatus({
          hash,
          hashBytes,
          transfer: bytes,
          destination: params.destination,
          energy: BigInt(params.energy),
          counter: counterValue,
        });
      },

      async importReceipt(receiptBase64) {
        await AESCounter;
        const receipt = Uint8Array.from(Buffer.from(receiptBase64, 'base64'));
        const transfer = await transferObject(receipt.slice(0, TRANSFER_LENGTH));

        if (!hashes.has(transfer.hash)) {
          let newEnergy = energy;
          if (transfer.destination !== transfer.source) {
            if ((await id) === transfer.destination) {
              newEnergy += transfer.energy;
            } else if ((await id) === transfer.source) {
              newEnergy -= transfer.energy;
              if (newEnergy < 0n) {
                newEnergy = 0n;
              }
            }
          }

          const { K12, schnorrq } = await crypto;

          const receiptView = new DataView(receipt.buffer);
          const digest = new Uint8Array(HASH_LENGTH);
          const message = receipt.slice(0, SIGNATURE_OFFSET);
          message[0] ^= 1;
          K12(message, digest, HASH_LENGTH);
          message[0] ^= 1;
          let offset = SIGNATURE_OFFSET;
          if (
            schnorrq.verify(
              receipt.slice(0, 32),
              digest,
              receipt.slice(offset, (offset += SIGNATURE_LENGTH))
            ) === 1
          ) {
            const computerStateDigest = new Uint8Array(HASH_LENGTH);
            K12(
              receipt.subarray(
                offset,
                (offset += COMPUTER_STATE_SIGNATURE_OFFSET - COMPUTER_STATE_COMPUTOR_INDEX_OFFSET)
              ),
              computerStateDigest,
              HASH_LENGTH
            );
            if (
              schnorrq.verify(
                adminPublicKeyBytes,
                computerStateDigest,
                receipt.slice(offset, (offset += COMPUTER_STATE_SIGNATURE_LENGTH))
              ) === 1
            ) {
              const computorPublicKeys = [];
              let computorPublicKeysOffset =
                TRANSFER_LENGTH +
                COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET -
                COMPUTER_STATE_COMPUTOR_INDEX_OFFSET;
              for (let i = 0; i < NUMBER_OF_COMPUTORS; i++) {
                computorPublicKeys.push(
                  receipt.subarray(
                    computorPublicKeysOffset + i * PUBLIC_KEY_LENGTH,
                    computorPublicKeysOffset + (i + 1) * PUBLIC_KEY_LENGTH
                  )
                );
              }

              const statuses = [];

              while (offset < receipt.length) {
                const transferStatusOffset =
                  offset + TRANSFER_STATUS_STATUS_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET;
                const digest = new Uint8Array(HASH_LENGTH);
                receipt[offset] ^= 3;
                K12(
                  receipt.subarray(
                    offset,
                    (offset += TRANSFER_STATUS_SIGNATURE_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET)
                  ),
                  digest,
                  HASH_LENGTH
                );
                receipt[
                  offset - (TRANSFER_STATUS_SIGNATURE_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET)
                ] ^= 3;
                const computorIndex = receiptView[
                  'getUint' + TRANSFER_STATUS_COMPUTOR_INDEX_LENGTH * 8
                ](
                  offset -
                    (TRANSFER_STATUS_SIGNATURE_OFFSET - TRANSFER_STATUS_DIGEST_OFFSET) +
                    TRANSFER_STATUS_COMPUTOR_INDEX_OFFSET -
                    TRANSFER_STATUS_DIGEST_OFFSET,
                  true
                );
                if (
                  schnorrq.verify(
                    computorPublicKeys[computorIndex],
                    digest,
                    receipt.subarray(offset, (offset += TRANSFER_STATUS_SIGNATURE_LENGTH))
                  ) === 1
                ) {
                  if (statuses[computorIndex] === undefined) {
                    statuses[computorIndex] = [];
                  }
                  for (let i = 0; i < TRANSFER_STATUS_STATUS_LENGTH; i++) {
                    for (let j = 0; j < 8; j += 2) {
                      let transferStatus = 0; // unseen
                      if (((receipt[transferStatusOffset + i] >> (8 - (j + 1))) & 0x0001) === 0) {
                        if (((receipt[transferStatusOffset + i] >> (8 - (j + 2))) & 0x0001) === 1) {
                          // 01 - seen
                          transferStatus = 1;
                        }
                      } else if (
                        ((receipt[transferStatusOffset + i] >> (8 - (j + 2))) & 0x0001) ===
                        0
                      ) {
                        // 10 - processed
                        transferStatus = 2;
                      }
                      statuses[computorIndex][i * 4 + j / 2] = transferStatus;
                    }
                  }
                }
              }

              const report = [0, 0, 0, 0];

              for (let i = 0; i < NUMBER_OF_COMPUTORS; i++) {
                for (let j = 0; j < NUMBER_OF_COMPUTORS; j++) {
                  if (i !== j) {
                    if (statuses[i] === undefined || statuses[i][j] === undefined) {
                      report[3] += 1;
                    } else {
                      report[statuses[i][j]] += 1;
                    }
                  }
                }
              }

              if (Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)) >= 451) {
                const counterValue = ++counter;
                hashesByIndex.set(counterValue, transfer.hashBytes);
                const energyCopy = energy;
                energy = newEnergy;

                const essence = databaseEssence();
                const secretKey = privateKey(seed, index, K12);
                const signature = schnorrq.sign(
                  secretKey,
                  schnorrq.generatePublicKey(secretKey),
                  essence
                );

                const counterBytes = new Uint8Array(4);
                const counterView = new DataView(counterBytes.buffer);
                counterView.setUint32(0, counterValue, true);
                const energyBytes = new Uint8Array(8);
                const energyView = new DataView(energyBytes.buffer);
                energyView.setBigUint64(0, energy, true);
                const transferAndReceipt = new Uint8Array(1 + receipt.length);
                transferAndReceipt[0] = 1;
                transferAndReceipt.set(receipt, 1);

                const key = new Uint8Array(16);
                K12(seedToBytes(seed), key, 16);

                const aes = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(counterValue));

                try {
                  await (
                    await database
                  )
                    .batch()
                    .put(counterValue, Buffer.from(aes.encrypt(transferAndReceipt)), {
                      valueEncoding: 'binary',
                    })
                    .put('counter', Buffer.from(counterBytes), {
                      valueEncoding: 'binary',
                    })
                    .put('energy', Buffer.from(energyBytes), {
                      valueEncoding: 'binary',
                    })
                    .put('signature', Buffer.from(signature), {
                      valueEncoding: 'binary',
                    })
                    .write();

                  that.emit('energy', energy);
                  that.emit('transfer', transfer);
                  that.emit('transferStatus', {
                    hash: transfer.hash,
                    unseen: Math.floor((report[3] + report[0]) / (NUMBER_OF_COMPUTORS - 1)),
                    seen: Math.floor(report[1] / (NUMBER_OF_COMPUTORS - 1)),
                    processed: Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)),
                  });
                  that.emit('receipt', {
                    hash: transfer.hash,
                    receipt,
                    receiptBase64,
                  });
                } catch {
                  energy = energyCopy;
                }

                transfers.add(transfer);
                hashes.add(transfer.hash);
              }
            }
          }
        }
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
        value = BigInt(value);
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
