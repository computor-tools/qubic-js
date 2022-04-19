'use strict';

import WebSocket from 'isomorphic-ws';
import EventEmitter from 'eventemitter2';
import { crypto } from './crypto/index.js';
import { bytesToShiftedHex, shiftedHexToBytes } from './utils/hex.js';
import { PUBLIC_KEY_LENGTH } from './identity.js';
import { timestamp } from './timestamp.js';
import { HASH_LENGTH, SIGNATURE_LENGTH, TRANSFER_LENGTH } from './transfer.js';

export const NUMBER_OF_COMPUTORS = 26 * 26;
const NUMBER_OF_CONNECTIONS = 3;

const PROTOCOL_VERSION = 256;
const REQUEST_TYPES = {
  WEBSOCKET: 0,
  EXCHANGE_PUBLIC_PEERS: 1,
  BROADCAST_TRANSFER: 3,
};

const SIZE_OFFSET = 0;
const SIZE_LENGTH = 4;
const PROTOCOL_VERSION_OFFSET = SIZE_OFFSET + SIZE_LENGTH;
const PROTOCOL_VERSION_LENGTH = 2;
const REQUEST_OFFSET = PROTOCOL_VERSION_OFFSET + PROTOCOL_VERSION_LENGTH;
const REQUEST_LENGTH = 2;
const HEADER_LENGTH = REQUEST_OFFSET + REQUEST_LENGTH;

const REQUEST_TYPE_OFFSET = HEADER_LENGTH;
const REQUEST_TYPE_LENGTH = 1;
const REQUEST_TYPE_PADDING = 7;
const REQUEST_TIMESTAMP_OFFSET = REQUEST_TYPE_OFFSET + REQUEST_TYPE_LENGTH + REQUEST_TYPE_PADDING;
const REQUEST_TIMESTAMP_LENGTH = 8;

const TRANSFER_STATUS_REQUEST_DIGEST_OFFSET = REQUEST_TIMESTAMP_OFFSET + REQUEST_TIMESTAMP_LENGTH;
const TRANSFER_STATUS_REQUEST_DIGEST_LENGTH = HASH_LENGTH;
const TRANSFER_STATUS_REQUEST_COMPUTOR_INDEX_OFFSET =
  TRANSFER_STATUS_REQUEST_DIGEST_OFFSET + TRANSFER_STATUS_REQUEST_DIGEST_LENGTH;
const TRANSFER_STATUS_REQUEST_COMPUTOR_INDEX_LENGTH = 2;
const TRANSFER_STATUS_REQUEST_LENGTH =
  TRANSFER_STATUS_REQUEST_COMPUTOR_INDEX_OFFSET + TRANSFER_STATUS_REQUEST_COMPUTOR_INDEX_LENGTH;

const WEBSOCKET_REQUEST_TYPES = {
  GET_COMPUTER_STATE: 1,
  GET_TRANSFER_STATUS: 3,
};

const RESPONSE_TYPE_OFFSET = HEADER_LENGTH;
const RESPONSE_TYPE_LENGTH = 1;
const RESPONSE_TYPE_PADDING = 7;
const RESPONSE_TIMESTAMP_OFFSET =
  RESPONSE_TYPE_OFFSET + RESPONSE_TYPE_LENGTH + RESPONSE_TYPE_PADDING;
const RESPONSE_TIMESTAMP_LENGTH = 8;

export const COMPUTER_STATE_COMPUTOR_INDEX_OFFSET =
  RESPONSE_TIMESTAMP_OFFSET + RESPONSE_TIMESTAMP_LENGTH;
const COMPUTER_STATE_COMPUTOR_INDEX_LENGTH = 2;
const COMPUTER_STATE_EPOCH_OFFSET =
  COMPUTER_STATE_COMPUTOR_INDEX_OFFSET + COMPUTER_STATE_COMPUTOR_INDEX_LENGTH;
const COMPUTER_STATE_EPOCH_LENGTH = 2;
const COMPUTER_STATE_TICK_OFFSET = COMPUTER_STATE_EPOCH_OFFSET + COMPUTER_STATE_EPOCH_LENGTH;
const COMPUTER_STATE_TICK_LENGTH = 4;
const COMPUTER_STATE_TIMESTAMP_OFFSET = COMPUTER_STATE_TICK_OFFSET + COMPUTER_STATE_TICK_LENGTH;
const COMPUTER_STATE_TIMESTAMP_LENGTH = 8;
export const COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET =
  COMPUTER_STATE_TIMESTAMP_OFFSET + COMPUTER_STATE_TIMESTAMP_LENGTH;
const COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_LENGTH = NUMBER_OF_COMPUTORS * PUBLIC_KEY_LENGTH;
export const COMPUTER_STATE_SIGNATURE_OFFSET =
  COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET + COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_LENGTH;
export const COMPUTER_STATE_SIGNATURE_LENGTH = SIGNATURE_LENGTH;

const PUBLIC_PEER_LENGTH = 4;
const NUMBER_OF_PUBLIC_PEERS = 4;

export const TRANSFER_STATUS_DIGEST_OFFSET = RESPONSE_TIMESTAMP_OFFSET + RESPONSE_TIMESTAMP_LENGTH;
const TRANSFER_STATUS_DIGEST_LENGTH = HASH_LENGTH;
export const TRANSFER_STATUS_STATUS_OFFSET =
  TRANSFER_STATUS_DIGEST_OFFSET + TRANSFER_STATUS_DIGEST_LENGTH;
export const TRANSFER_STATUS_STATUS_LENGTH = (NUMBER_OF_COMPUTORS * 2) / 8;
const TRANSFER_STATUS_STATUS_PADDING = 3;
export const TRANSFER_STATUS_COMPUTOR_INDEX_OFFSET =
  TRANSFER_STATUS_STATUS_OFFSET + TRANSFER_STATUS_STATUS_LENGTH + TRANSFER_STATUS_STATUS_PADDING;
export const TRANSFER_STATUS_COMPUTOR_INDEX_LENGTH = 2;
const TRANSFER_STATUS_EPOCH_OFFSET =
  TRANSFER_STATUS_COMPUTOR_INDEX_OFFSET + TRANSFER_STATUS_COMPUTOR_INDEX_LENGTH;
const TRANSFER_STATUS_EPOCH_LENGTH = 2;
const TRANSFER_STATUS_TICK_OFFSET = TRANSFER_STATUS_EPOCH_OFFSET + TRANSFER_STATUS_EPOCH_LENGTH;
const TRANSFER_STATUS_TICK_LENGTH = 4;
export const TRANSFER_STATUS_SIGNATURE_OFFSET =
  TRANSFER_STATUS_TICK_OFFSET + TRANSFER_STATUS_TICK_LENGTH;
export const TRANSFER_STATUS_SIGNATURE_LENGTH = SIGNATURE_LENGTH;
const TRANSFER_STATUS_LENGTH = TRANSFER_STATUS_SIGNATURE_OFFSET + TRANSFER_STATUS_SIGNATURE_LENGTH;

const compareResponses = function (
  responses,
  status,
  rightOffset,
  leftOffset = 0,
  recompare = true
) {
  while (rightOffset < responses.length) {
    let equal = true;
    for (let j = 0; j < SIGNATURE_LENGTH; j++) {
      if (responses[leftOffset][j] !== responses[rightOffset][j]) {
        equal = false;
        break;
      }
    }
    if (equal) {
      status += 1;
    }
    rightOffset++;
  }
  if (responses.length === NUMBER_OF_CONNECTIONS && status === 1 && recompare) {
    return compareResponses(responses, status, 2, 1, false);
  }
  return { status, rightOffset };
};

/**
 * @function connection
 * @memberof module:qubic
 * @param {object} params - Connection params.
 * @param {object[]} params.peers - Specifies 3 computors to connect to, and with what options.
 * @param {string} params.adminPublicKey - Admin public key, for verification of current epoch and tick which are signed by admin.
 * @param {number} params.connectionTimeoutDuration - Connection timeout duration in milliseconds.
 * @param {number} params.computerStateSynchronizationDelayDuration - Max delay to wait for computer state response.
 * @param {number} [params.computerStateSynchronizationTimeoutDuration] - If no new tick appears after this timeout, an info event is emitted with updated computer state.
 * @fires Connection#info
 * @fires Connection#open
 * @fires Connection#close
 * @fires Connection#error
 * @returns {Connection}
 * @example import qubic from 'qubic-js';
 *
 * const connection = qubic.connection({
 *   ips: ['?.?.?.?', '?.?.?.?', '?.?.?.?'],
 *   computerStateSynchronizationTimeoutDuration: 60 * 1000,
 *   adminPublicKey: '97CC65D1E59351EEFC776BCFF197533F148A8105DA84129C051F70DD9CA0FF82',
 * });
 *
 * connection.addListener('error', function (error) {
 *   console.log(error.message);
 * });
 * connection.addListener('info', console.log);
 *
 */
export const connection = function ({
  peers,
  adminPublicKey,
  connectionTimeoutDuration = 3000,
  computerStateSynchronizationTimeoutDuration = 500,
  computerStateSynchronizationDelayDuration = 500,
}) {
  let sockets = [];
  let latestComputerState = {
    status: 0,
  };
  let latestComputerStateSynchronizationTimestamp = 0;
  let latestComputerStateRequestTimestamp = 0n;
  let computerStateComparisonRightOffset = 1;
  let computerStateSynchronizationTimeout;

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

  const publicPeers = [];

  const computerStateResponsesByTimestamp = new Map();
  const transferStatusResponsesStateByDigest = new Map();
  const transferStatusRequestsToResendByDigest = new Map();

  const getComputerState = function () {
    const length =
      HEADER_LENGTH + REQUEST_TYPE_LENGTH + REQUEST_TYPE_PADDING + REQUEST_TIMESTAMP_LENGTH;
    const request = new Uint8Array(length);
    const requestView = new DataView(request.buffer);
    const ts = timestamp();
    computerStateResponsesByTimestamp.delete(latestComputerStateRequestTimestamp);
    latestComputerStateRequestTimestamp = ts;
    requestView['setUint' + SIZE_LENGTH * 8](SIZE_OFFSET, length, true);
    requestView['setUint' + PROTOCOL_VERSION_LENGTH * 8](
      PROTOCOL_VERSION_OFFSET,
      PROTOCOL_VERSION,
      true
    );
    requestView['setUint' + REQUEST_LENGTH * 8](REQUEST_OFFSET, REQUEST_TYPES.WEBSOCKET, true);
    request[REQUEST_TYPE_OFFSET] = WEBSOCKET_REQUEST_TYPES.GET_COMPUTER_STATE;
    requestView.setBigUint64(REQUEST_TIMESTAMP_OFFSET, ts, true);

    computerStateResponsesByTimestamp.set(ts, []);

    sockets.forEach(function (socket) {
      socket.open.then(function () {
        if (socket.readyState === 1) {
          socket.send(request.buffer);
        }
      });
    });
  };

  const exchangePublicPeers = function (socket) {
    const length = HEADER_LENGTH + NUMBER_OF_PUBLIC_PEERS * PUBLIC_PEER_LENGTH;
    const request = new Uint8Array(length);
    const requestView = new DataView(request.buffer);
    requestView['setUint' + SIZE_LENGTH * 8](SIZE_OFFSET, length, true);
    requestView['setUint' + PROTOCOL_VERSION_LENGTH * 8](
      PROTOCOL_VERSION_OFFSET,
      PROTOCOL_VERSION,
      true
    );
    requestView['setUint' + REQUEST_LENGTH * 8](
      REQUEST_OFFSET,
      REQUEST_TYPES.EXCHANGE_PUBLIC_PEERS,
      true
    );
    socket.open.then(function () {
      if (socket.readyState === 1) {
        socket.send(request.buffer);
      }
    });
  };

  const broadcastTransfer = function (transfer) {
    const length = HEADER_LENGTH + TRANSFER_LENGTH;
    const request = new Uint8Array(length);
    const requestView = new DataView(request.buffer);
    requestView['setUint' + SIZE_LENGTH * 8](SIZE_OFFSET, length, true);
    requestView['setUint' + PROTOCOL_VERSION_LENGTH * 8](
      PROTOCOL_VERSION_OFFSET,
      PROTOCOL_VERSION,
      true
    );
    requestView['setUint' + REQUEST_LENGTH * 8](
      REQUEST_OFFSET,
      REQUEST_TYPES.BROADCAST_TRANSFER,
      true
    );
    request.set(transfer, HEADER_LENGTH);

    sockets.forEach(function (socket) {
      socket.open.then(function () {
        if (socket.readyState === 1) {
          socket.send(request.buffer);
        }
      });
    });
  };

  const getTransferStatus = async function (digest) {
    let state = transferStatusResponsesStateByDigest.get(digest);
    if (state === undefined) {
      state = {};
      state.responses = Array(NUMBER_OF_COMPUTORS).fill(Array(NUMBER_OF_CONNECTIONS));
      state.resolvers = [];
    } else {
      state.responses.fill(Array(NUMBER_OF_CONNECTIONS));
    }
    state.requestTimestamp = timestamp();
    state.processedFlags = Array(NUMBER_OF_COMPUTORS).fill(false);
    state.computorReports = [];
    // TODO: wait for computer state to be initialized.
    state.computerState = {
      ...latestComputerState,
      computorPublicKeys: [...latestComputerState.computorPublicKeys],
      bytes: [...latestComputerState.bytes],
    };
    state.transferStatusComparisonStatuses = Array(NUMBER_OF_COMPUTORS).fill(1);
    state.transferStatusComparisonRightOffsets = Array(NUMBER_OF_COMPUTORS).fill(1);
    state.statuses = [];
    transferStatusResponsesStateByDigest.set(digest, state);

    const promise = new Promise(function (resolve) {
      state.resolvers.push(resolve);
    });

    const request = new Uint8Array(TRANSFER_STATUS_REQUEST_LENGTH);
    const requestView = new DataView(request.buffer);

    requestView['setUint' + SIZE_LENGTH * 8](SIZE_OFFSET, TRANSFER_STATUS_REQUEST_LENGTH, true);
    requestView['setUint' + PROTOCOL_VERSION_LENGTH * 8](
      PROTOCOL_VERSION_OFFSET,
      PROTOCOL_VERSION,
      true
    );
    requestView['setUint' + REQUEST_LENGTH * 8](REQUEST_OFFSET, REQUEST_TYPES.WEBSOCKET, true);
    request[REQUEST_TYPE_OFFSET] = WEBSOCKET_REQUEST_TYPES.GET_TRANSFER_STATUS;
    requestView.setBigUint64(REQUEST_TIMESTAMP_OFFSET, state.requestTimestamp, true);

    request.set(shiftedHexToBytes(digest.toLowerCase()), TRANSFER_STATUS_REQUEST_DIGEST_OFFSET);

    const requestsToResend = [];
    for (let i = 0; i < NUMBER_OF_COMPUTORS; i++) {
      // TODO: stop sending if status is determined.
      await new Promise(function (resolve) {
        setTimeout(function () {
          resolve();
        }, 100);
      });

      requestView['setUint' + TRANSFER_STATUS_REQUEST_COMPUTOR_INDEX_LENGTH * 8](
        TRANSFER_STATUS_REQUEST_COMPUTOR_INDEX_OFFSET,
        i,
        true
      );

      const request2 = request.slice();
      requestsToResend.push(request2);

      sockets.forEach(function (socket) {
        socket.open.then(function () {
          if (socket.readyState === 1) {
            socket.send(request2.buffer);
          }
        });
      });
    }
    transferStatusRequestsToResendByDigest.set(digest, requestsToResend);

    return promise;
  };

  /**
   * @mixin Connection
   */

  /**
   * Terminates all 3 WebSocket connections.
   *
   * @function close
   * @memberof Connection
   */
  const close = function () {
    sockets.forEach(function (socket) {
      socket.terminate();
    });
    clearTimeout(computerStateSynchronizationTimeout);
    latestComputerState.status = 0;
    this.emit('info', {
      computerState: {
        ...latestComputerState,
        computorPublicKeys: [...latestComputerState.computorPublicKeys],
      },
      peers: sockets.map(function ({ ip, readyState }) {
        return { ip, readyState };
      }),
    });
  };

  const connectionMixin = function () {
    const that = this;

    const computerStateSynchronizationRoutine = function () {
      if (
        Date.now() - latestComputerStateSynchronizationTimestamp >
        computerStateSynchronizationTimeoutDuration + computerStateSynchronizationDelayDuration
      ) {
        latestComputerState.status = 0;
        computerStateComparisonRightOffset = 1;
        that.emit('info', {
          computerState: latestComputerState,
          peers: sockets.map(function ({ ip, readyState }) {
            return { ip, readyState };
          }),
        });
      }
      computerStateSynchronizationTimeout = setTimeout(
        computerStateSynchronizationRoutine,
        computerStateSynchronizationTimeoutDuration + computerStateSynchronizationDelayDuration
      );
    };

    /**
     * Sets one of the 3 computors IPs each time.
     *
     * @function setPeer
     * @param {number} index - Index of computor connection, 0, 1 or 2.
     * @param ip
     * @param {string} ip - Computor IP.
     * @memberof Connection
     */
    const setPeer = function (index, ip) {
      if (sockets[index].ip !== ip) {
        sockets[index].terminate();
        open(index, ip);
      }
    };

    const open = function (index, ip) {
      if (index === undefined) {
        sockets = [];
      }

      const openSocket = function (i) {
        const socket = (sockets[i] = new WebSocket(
          ip ? `ws://${ip}:21841` : `ws://${peers[i]}:21841`
        ));
        sockets[i].i = i;
        sockets[i].binaryType = 'arraybuffer';
        sockets[i].ip = ip || peers[i];

        let resolveOnOpenOrClose;
        socket.open = new Promise(function (resolve) {
          resolveOnOpenOrClose = resolve;
        });

        const timeout = setTimeout(function () {
          socket.close();
        }, connectionTimeoutDuration);

        socket.terminate = function () {
          clearTimeout(timeout);
          socket.onclose = undefined;
          socket.close();
        };

        socket.onopen = function (event) {
          clearTimeout(timeout);
          /**
           * Open event. Emitted when a WebSocket connection opens.
           *
           * @event Connection#open
           * @param {event} event - WebSocket event.
           */
          that.emit('open', event);
          that.emit('info', {
            computerState: latestComputerState,
            peers: sockets.map(function ({ ip, readyState }) {
              return { ip, readyState };
            }),
          });
          exchangePublicPeers(socket);
          resolveOnOpenOrClose();

          transferStatusRequestsToResendByDigest.forEach(async function (requests) {
            requests.forEach(async function (request) {
              await new Promise(function (resolve) {
                setTimeout(function () {
                  resolve();
                }, 100);
              });
              if (socket.readyState === 1) {
                socket.send(request.buffer);
              }
            });
          });
        };

        socket.onmessage = async function (message) {
          let offset = 0;
          const data = new Uint8Array(message.data);
          const dataView = new DataView(message.data);
          while (offset < data.length) {
            const response = data.subarray(
              offset,
              offset + dataView['getUint' + SIZE_LENGTH * 8](SIZE_OFFSET, true)
            );
            const responseView = new DataView(response.buffer);

            switch (responseView['getUint' + REQUEST_LENGTH * 8](REQUEST_OFFSET, true)) {
              case REQUEST_TYPES.WEBSOCKET:
                switch (response[RESPONSE_TYPE_OFFSET]) {
                  case WEBSOCKET_REQUEST_TYPES.GET_COMPUTER_STATE:
                    {
                      const computorIndex = responseView[
                        'getUint' + COMPUTER_STATE_COMPUTOR_INDEX_LENGTH * 8
                      ](COMPUTER_STATE_COMPUTOR_INDEX_OFFSET, true);

                      if (computorIndex === NUMBER_OF_COMPUTORS) {
                        const hash = new Uint8Array(HASH_LENGTH);
                        (await crypto).K12(
                          response.slice(
                            COMPUTER_STATE_COMPUTOR_INDEX_OFFSET,
                            COMPUTER_STATE_SIGNATURE_OFFSET
                          ),
                          hash,
                          HASH_LENGTH
                        );
                        if (
                          (await crypto).schnorrq.verify(
                            adminPublicKeyBytes,
                            hash,
                            response.slice(
                              COMPUTER_STATE_SIGNATURE_OFFSET,
                              COMPUTER_STATE_SIGNATURE_OFFSET + COMPUTER_STATE_SIGNATURE_LENGTH
                            )
                          ) === 1
                        ) {
                          const responseTimestamp = responseView.getBigUint64(
                            RESPONSE_TIMESTAMP_OFFSET,
                            true
                          );
                          const timestamp = responseView.getBigUint64(
                            COMPUTER_STATE_TIMESTAMP_OFFSET,
                            true
                          );
                          const responses =
                            computerStateResponsesByTimestamp.get(responseTimestamp);
                          if (responses !== undefined) {
                            responses[socket.i] = response;

                            if (responses.length === 1) {
                              latestComputerState.status = 1;
                              that.emit('info', {
                                computerState: {
                                  ...latestComputerState,
                                  computorPublicKeys: [
                                    ...(latestComputerState?.computorPublicKeys || []),
                                  ],
                                },
                                peers: sockets.map(function ({ ip, readyState }) {
                                  return { ip, readyState };
                                }),
                              });
                              return;
                            }

                            const { status, rightOffset } = compareResponses(
                              responses
                                .filter(function (response) {
                                  return response !== undefined;
                                })
                                .map(function (response) {
                                  return response.subarray(
                                    COMPUTER_STATE_SIGNATURE_OFFSET,
                                    COMPUTER_STATE_SIGNATURE_OFFSET +
                                      COMPUTER_STATE_SIGNATURE_LENGTH
                                  );
                                }),
                              latestComputerState.status,
                              computerStateComparisonRightOffset
                            );

                            computerStateComparisonRightOffset = rightOffset;

                            if (latestComputerState.status < status) {
                              latestComputerStateSynchronizationTimestamp = Date.now();
                              latestComputerState = {
                                status,
                                epoch: responseView['getUint' + COMPUTER_STATE_EPOCH_LENGTH * 8](
                                  COMPUTER_STATE_EPOCH_OFFSET,
                                  true
                                ),
                                tick: responseView['getUint' + COMPUTER_STATE_TICK_LENGTH * 8](
                                  COMPUTER_STATE_TICK_OFFSET,
                                  true
                                ),
                                timestamp,
                                computorPublicKeys: Array(NUMBER_OF_COMPUTORS),
                                bytes: response.slice(
                                  COMPUTER_STATE_COMPUTOR_INDEX_OFFSET,
                                  COMPUTER_STATE_SIGNATURE_OFFSET + COMPUTER_STATE_SIGNATURE_LENGTH
                                ),
                              };

                              let offset = COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET;
                              latestComputerState.computorPublicKeys.length = 0;
                              while (
                                offset <
                                COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_OFFSET +
                                  COMPUTER_STATE_COMPUTOR_PUBLIC_KEYS_LENGTH
                              ) {
                                latestComputerState.computorPublicKeys.push(
                                  response.subarray(offset, (offset += PUBLIC_KEY_LENGTH))
                                );
                              }

                              /**
                               * Info event.
                               *
                               * @event Connection#info
                               * @type {object}
                               * @property {number} status - Indicates which of the 3 computors have provided the same tick and epoch.
                               * 0 when offline, 3 when fully synced.
                               * @property {number} epoch - Current epoch.
                               * @property {number} tick - Current tick.
                               */
                              that.emit('info', {
                                computerState: {
                                  ...latestComputerState,
                                  computorPublicKeys: [...latestComputerState.computorPublicKeys],
                                },
                                peers: sockets.map(function ({ ip, readyState }) {
                                  return { ip, readyState };
                                }),
                              });
                            }

                            if (responses.length === NUMBER_OF_COMPUTORS) {
                              latestComputerState.status = 0;
                              computerStateResponsesByTimestamp.delete(responseTimestamp);
                            }
                          }
                        }
                      }
                    }
                    break;
                  case WEBSOCKET_REQUEST_TYPES.GET_TRANSFER_STATUS: {
                    for (
                      let offset = 0;
                      offset < response.length;
                      offset += TRANSFER_STATUS_LENGTH
                    ) {
                      const digest = bytesToShiftedHex(
                        response.subarray(
                          offset + TRANSFER_STATUS_DIGEST_OFFSET,
                          offset + TRANSFER_STATUS_DIGEST_OFFSET + TRANSFER_STATUS_DIGEST_LENGTH
                        )
                      ).toUpperCase();
                      const state = transferStatusResponsesStateByDigest.get(digest);
                      const ts = responseView.getBigUint64(RESPONSE_TIMESTAMP_OFFSET, true);
                      if (state !== undefined && state.requestTimestamp === ts) {
                        const computorIndex = responseView[
                          'getUint' + TRANSFER_STATUS_COMPUTOR_INDEX_LENGTH * 8
                        ](offset + TRANSFER_STATUS_COMPUTOR_INDEX_OFFSET, true);
                        const epoch = responseView['getUint' + TRANSFER_STATUS_EPOCH_LENGTH * 8](
                          offset + TRANSFER_STATUS_EPOCH_OFFSET,
                          true
                        );
                        const tick = responseView['getUint' + TRANSFER_STATUS_TICK_LENGTH * 8](
                          offset + TRANSFER_STATUS_TICK_OFFSET,
                          true
                        );
                        if (
                          epoch === state.computerState.epoch &&
                          tick <= state.computerState.tick
                        ) {
                          const messageDigest = new Uint8Array(HASH_LENGTH);
                          response[offset + TRANSFER_STATUS_DIGEST_OFFSET] ^= 3;
                          (await crypto).K12(
                            response.subarray(
                              offset + TRANSFER_STATUS_DIGEST_OFFSET,
                              offset + TRANSFER_STATUS_SIGNATURE_OFFSET
                            ),
                            messageDigest,
                            HASH_LENGTH
                          );
                          response[offset + TRANSFER_STATUS_DIGEST_OFFSET] ^= 3;
                          if (
                            (await crypto).schnorrq.verify(
                              state.computerState.computorPublicKeys[computorIndex],
                              messageDigest,
                              response.subarray(
                                offset + TRANSFER_STATUS_SIGNATURE_OFFSET,
                                offset +
                                  TRANSFER_STATUS_SIGNATURE_OFFSET +
                                  TRANSFER_STATUS_SIGNATURE_LENGTH
                              )
                            ) === 1
                          ) {
                            state.responses[computorIndex][socket.i] = response.subarray(
                              offset,
                              offset + TRANSFER_STATUS_LENGTH
                            );
                            const { status, rightOffset } = compareResponses(
                              state.responses[computorIndex]
                                .filter(function (response) {
                                  return response !== undefined;
                                })
                                .map(function (response) {
                                  return response.subarray(
                                    TRANSFER_STATUS_STATUS_OFFSET,
                                    TRANSFER_STATUS_STATUS_OFFSET + TRANSFER_STATUS_STATUS_LENGTH
                                  );
                                }),
                              state.transferStatusComparisonStatuses[computorIndex],
                              state.transferStatusComparisonRightOffsets[computorIndex]
                            );

                            state.transferStatusComparisonStatuses[computorIndex] = status;
                            state.transferStatusComparisonRightOffsets[computorIndex] = rightOffset;

                            if (
                              status >= 1 &&
                              state.processedFlags[computorIndex] === false &&
                              (state.processedFlags[computorIndex] = true)
                            ) {
                              if (state.statuses[computorIndex] === undefined) {
                                state.statuses[computorIndex] = [];
                              }
                              let hasReportedProcessed = false;
                              for (let i = 0; i < TRANSFER_STATUS_STATUS_LENGTH; i++) {
                                for (let j = 0; j < 8; j += 2) {
                                  let transferStatus = 0; // unseen
                                  if (
                                    ((response[offset + TRANSFER_STATUS_STATUS_OFFSET + i] >>
                                      (8 - (j + 1))) &
                                      0x0001) ===
                                    0
                                  ) {
                                    if (
                                      ((response[offset + TRANSFER_STATUS_STATUS_OFFSET + i] >>
                                        (8 - (j + 2))) &
                                        0x0001) ===
                                      1
                                    ) {
                                      // 01 - seen
                                      transferStatus = 1;
                                    }
                                  } else if (
                                    ((response[offset + TRANSFER_STATUS_STATUS_OFFSET + i] >>
                                      (8 - (j + 2))) &
                                      0x0001) ===
                                    0
                                  ) {
                                    // 10 - processed
                                    transferStatus = 2;
                                    hasReportedProcessed = true;
                                  }
                                  state.statuses[computorIndex][i * 4 + j / 2] = transferStatus;
                                }
                              }

                              if (hasReportedProcessed) {
                                state.computorReports.push(
                                  response.slice(
                                    offset + TRANSFER_STATUS_DIGEST_OFFSET,
                                    offset +
                                      TRANSFER_STATUS_SIGNATURE_OFFSET +
                                      TRANSFER_STATUS_SIGNATURE_LENGTH
                                  )
                                );
                              }

                              const report = [0, 0, 0, 0];

                              for (let i = 0; i < NUMBER_OF_COMPUTORS; i++) {
                                for (let j = 0; j < NUMBER_OF_COMPUTORS; j++) {
                                  if (i !== j) {
                                    if (
                                      state.statuses[i] === undefined ||
                                      state.statuses[i][j] === undefined
                                    ) {
                                      report[3] += 1;
                                    } else {
                                      report[state.statuses[i][j]] += 1;
                                    }
                                  }
                                }
                              }

                              that.emit('transferStatus', {
                                hash: digest,
                                unseen: Math.floor(
                                  (report[3] + report[0]) / (NUMBER_OF_COMPUTORS - 1)
                                ),
                                seen: Math.floor(report[1] / (NUMBER_OF_COMPUTORS - 1)),
                                processed: Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)),
                                epoch,
                                tick,
                              });

                              if (
                                Math.floor(report[0] / (NUMBER_OF_COMPUTORS - 1)) >= 451 ||
                                Math.floor(report[1] / (NUMBER_OF_COMPUTORS - 1)) >= 451 ||
                                Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)) >= 451
                              ) {
                                transferStatusResponsesStateByDigest.delete(digest);
                                transferStatusRequestsToResendByDigest.delete(digest);

                                let receipt;
                                if (Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)) >= 451) {
                                  receipt = new Uint8Array(
                                    state.computerState.bytes.length +
                                      state.computorReports.length *
                                        (TRANSFER_STATUS_SIGNATURE_OFFSET +
                                          TRANSFER_STATUS_SIGNATURE_LENGTH -
                                          TRANSFER_STATUS_DIGEST_OFFSET)
                                  );
                                  receipt.set(state.computerState.bytes, 0);
                                  for (
                                    let i = 0, offset = state.computerState.bytes.length;
                                    offset < receipt.length;
                                    offset +=
                                      TRANSFER_STATUS_SIGNATURE_OFFSET +
                                      TRANSFER_STATUS_SIGNATURE_LENGTH -
                                      TRANSFER_STATUS_DIGEST_OFFSET
                                  ) {
                                    receipt.set(state.computorReports[i++], offset);
                                  }
                                }

                                state.resolvers.forEach(function (resolve) {
                                  resolve({
                                    hash: digest,
                                    receipt,
                                    unseen: Math.floor(
                                      (report[3] + report[0]) / (NUMBER_OF_COMPUTORS - 1)
                                    ),
                                    seen: Math.floor(report[1] / (NUMBER_OF_COMPUTORS - 1)),
                                    processed: Math.floor(report[2] / (NUMBER_OF_COMPUTORS - 1)),
                                    epoch,
                                    tick,
                                  });
                                });
                              }

                              state.responses[computorIndex] = Array(NUMBER_OF_COMPUTORS);
                            }
                          }
                        }
                      }
                    }
                  }
                }
                break;
              case REQUEST_TYPES.EXCHANGE_PUBLIC_PEERS:
                for (
                  let offset = HEADER_LENGTH;
                  offset < HEADER_LENGTH + NUMBER_OF_PUBLIC_PEERS * PUBLIC_PEER_LENGTH;
                  offset += PUBLIC_PEER_LENGTH
                ) {
                  const peer = response.subarray(offset, offset + PUBLIC_PEER_LENGTH).join('.');
                  publicPeers.push(peer);
                }
                sockets.forEach(function ({ i }) {
                  if (sockets[i].readyState === 3) {
                    const peer = publicPeers.shift();
                    if (peer !== undefined) {
                      setPeer(i, peer);
                    }
                  }
                });
            }
            offset += response.length;
          }
        };

        socket.onerror = function (event) {
          /**
           * Error event. Emitted when a WebSocket connection errors.
           *
           * @event Connection#error
           * @param {event} event - WebSocket event.
           */
          that.emit('error', event);
          this.close();
        };

        socket.onclose = function (event) {
          clearTimeout(timeout);
          /**
           * Close event. Emitted when a WebSocket connection closes.
           *
           * @event Connection#close
           * @param {event} event - WebSocket event.
           */
          that.emit('close', event);
          resolveOnOpenOrClose();

          const peer = publicPeers.shift();
          if (peer !== undefined) {
            setPeer(i, peer);
          }
          if (publicPeers.length === 0) {
            const openSocket = sockets.filter(function ({ readyState }) {
              return readyState === 1;
            })[0];
            if (openSocket !== undefined) {
              exchangePublicPeers(openSocket);
            }
          }
        };
      };

      if (index === undefined) {
        for (let i = 0; i < NUMBER_OF_CONNECTIONS; i++) {
          openSocket(i);
        }

        const getComputerStateRoutine = function () {
          getComputerState();
          setTimeout(getComputerStateRoutine, computerStateSynchronizationTimeoutDuration);
        };
        getComputerStateRoutine();
        computerStateSynchronizationRoutine(that);
      } else {
        openSocket(index);
      }
    };

    return Object.assign(
      that,
      {
        /**
         * Opens all 3 WebSocket connections.
         *
         * @function open
         * @memberof Connection
         * @fires Connection#info
         * @fires Connection#open
         * @fires Connection#close
         * @fires Connection#error
         */
        open: function () {
          open();
        },
        close,
        broadcastTransfer,
        getTransferStatus,
        setPeer,
        /**
         * @function computors
         * @memberof Connection
         * @returns {string[]} Array of computor IPs and states.
         */
        peers() {
          return sockets.map(function ({ ip, readyState }) {
            return { ip, readyState };
          });
        },
      },
      EventEmitter.prototype
    );
  };

  const connection = connectionMixin.call({});
  connection.open();
  return connection;
};
