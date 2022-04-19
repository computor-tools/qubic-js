import ws from 'isomorphic-ws';
import { crypto } from './crypto/index.js';
import { privateKey } from './identity.js';
import { timestamp } from './timestamp.js';
import { bytesToShiftedHex } from './utils/hex.js';

const PROTOCOL_VERSION = 256;
const REQUEST = 0;

const SIZE_OFFSET = 0;
const SIZE_LENGTH = 4;
const PROTOCOL_VERSION_OFFSET = SIZE_OFFSET + SIZE_LENGTH;
const PROTOCOL_VERSION_LENGTH = 2;
const REQUEST_OFFSET = PROTOCOL_VERSION_OFFSET + PROTOCOL_VERSION_LENGTH;
const REQUEST_LENGTH = 2;
const HEADER_LENGTH = SIZE_LENGTH + PROTOCOL_VERSION_LENGTH + REQUEST_LENGTH;

const REQUEST_TYPE_OFFSET = HEADER_LENGTH;
const REQUEST_TYPE_LENGTH = 1;
const REQUEST_TYPE_PADDING = 7;
const TIMESTAMP_OFFSET = REQUEST_TYPE_OFFSET + REQUEST_TYPE_LENGTH + REQUEST_TYPE_PADDING;
const TIMESTAMP_LENGTH = 8;

const DIGEST_LENGTH = 32;
const SIGNATURE_LENGTH = 64;

const REQUEST_TYPES = {
  SHUTDOWN: -1,
  GET_NODE_INFO: -2,
};

const ROLES = ['COMPUTOR', 'MINER', 'USER'];

const RESPONSE_TYPE_OFFSET = HEADER_LENGTH;
const RESPONSE_TYPE_LENGTH = 1;

const ROLE_OFFSET = RESPONSE_TYPE_OFFSET + RESPONSE_TYPE_LENGTH;
const ROLE_LENGTH = 1;
const ROLE_PADDING = 2;
const OWN_PUBLIC_KEY_OFFSET = ROLE_OFFSET + ROLE_LENGTH + ROLE_PADDING;
const OWN_PUBLIC_KEY_LENGTH = 32;
const NUMBER_OF_PROCESSORS_OFFSET = OWN_PUBLIC_KEY_OFFSET + OWN_PUBLIC_KEY_LENGTH;
const NUMBER_OF_PROCESSORS_LENGTH = 2;
const NUMBER_OF_BUSY_PROCESSORS_OFFSET = NUMBER_OF_PROCESSORS_OFFSET + NUMBER_OF_PROCESSORS_LENGTH;
const NUMBER_OF_BUSY_PROCESSORS_LENGTH = 2;
const LAUNCH_TIME_OFFSET = NUMBER_OF_BUSY_PROCESSORS_OFFSET + NUMBER_OF_BUSY_PROCESSORS_LENGTH;
const LAUNCH_TIME_LENGTH = 8;
const NUMBER_OF_PROCESSED_REQUESTS_OFFSET = LAUNCH_TIME_OFFSET + LAUNCH_TIME_LENGTH;
const NUMBER_OF_PROCESSED_REQUESTS_LENGTH = 8;
const NUMBER_OF_RECEIVED_BYTES_OFFSET =
  NUMBER_OF_PROCESSED_REQUESTS_OFFSET + NUMBER_OF_PROCESSED_REQUESTS_LENGTH;
const NUMBER_OF_RECEIVED_BYTES_LENGTH = 8;
const NUMBER_OF_TRANSMITTED_BYTES_OFFSET =
  NUMBER_OF_RECEIVED_BYTES_OFFSET + NUMBER_OF_RECEIVED_BYTES_LENGTH;
const NUMBER_OF_TRANSMITTED_BYTES_LENGTH = 8;
const NUMBER_OF_PEERS_OFFSET =
  NUMBER_OF_TRANSMITTED_BYTES_OFFSET + NUMBER_OF_TRANSMITTED_BYTES_LENGTH;
const NUMBER_OF_PEERS_LENGTH = 4;

export const computor = function ({ seed, url, reconnectTimeoutDuration }) {
  const secretKey = crypto.then(function ({ K12 }) {
    return privateKey(seed, 0, K12);
  });
  const publicKey = secretKey.then(function (sk) {
    return crypto.then(function ({ schnorrq }) {
      return schnorrq.generatePublicKey(sk);
    });
  });

  let closed = true;
  let socket;
  let reconnectTimeout;
  const requestsByType = new Map();
  const responsesByType = new Map();

  const open = function () {
    if (closed === true) {
      closed = false;
      socket = new ws(url);
      socket.binaryType = 'arraybuffer';

      let resolveOnOpen;
      socket.open = new Promise(function (resolve) {
        resolveOnOpen = resolve;
      });

      socket.onopen = function () {
        resolveOnOpen();
        console.log('open');

        requestsByType.forEach(function (requests) {
          requests.forEach(function (request, i) {
            socket.open.then(function () {
              socket.send(request);
              requests.splice(i, 1);
            });
          });
        });
      };

      socket.onclose = function () {
        closed = true;
        reconnectTimeout = setTimeout(open, reconnectTimeoutDuration);
      };

      socket.onmessage = function (message) {
        const response = new Uint8Array(message.data);
        const responseView = new DataView(message.data);
        console.log(response);
        const responses = responsesByType.get(response[RESPONSE_TYPE_OFFSET]);
        if (responses !== undefined) {
          const { resolve } = responses.shift(responses);

          switch ((response[RESPONSE_TYPE_OFFSET] << 24) >> 24) {
            case REQUEST_TYPES.GET_NODE_INFO:
              resolve({
                role: ROLES[response[ROLE_OFFSET]],
                ownPublicKey: bytesToShiftedHex(
                  response.subarray(
                    OWN_PUBLIC_KEY_OFFSET,
                    OWN_PUBLIC_KEY_OFFSET + OWN_PUBLIC_KEY_LENGTH
                  )
                ).toUpperCase(),
                numberOfProcessors: responseView['getUint' + NUMBER_OF_PROCESSORS_LENGTH * 8](
                  NUMBER_OF_PROCESSORS_OFFSET,
                  true
                ),
                numberOfBusyProcessors: responseView[
                  'getUint' + NUMBER_OF_BUSY_PROCESSORS_LENGTH * 8
                ](NUMBER_OF_BUSY_PROCESSORS_OFFSET, true),
                cpuLoad:
                  Math.round(
                    ((responseView['getUint' + NUMBER_OF_BUSY_PROCESSORS_LENGTH * 8](
                      NUMBER_OF_BUSY_PROCESSORS_OFFSET,
                      true
                    ) *
                      100) /
                      responseView['getUint' + NUMBER_OF_PROCESSORS_LENGTH * 8](
                        NUMBER_OF_PROCESSORS_OFFSET,
                        true
                      )) *
                      100
                  ) / 100,
                launchTime: responseView.getBigUint64(LAUNCH_TIME_OFFSET, true),
                numberOfProcessedRequests: responseView.getBigUint64(
                  NUMBER_OF_PROCESSED_REQUESTS_OFFSET,
                  true
                ),
                numberOfReceivedBytes: responseView.getBigUint64(
                  NUMBER_OF_RECEIVED_BYTES_OFFSET,
                  true
                ),
                numberOfTransmittedBytes: responseView.getBigUint64(
                  NUMBER_OF_TRANSMITTED_BYTES_OFFSET,
                  true
                ),
                numberOfPeers: responseView['getUint' + NUMBER_OF_PEERS_LENGTH * 8](
                  NUMBER_OF_PEERS_OFFSET,
                  true
                ),
              });
              break;

            default:
              break;
          }
        }
      };
    }
  };
  open();

  const close = function () {
    socket.onclose = undefined;
    clearTimeout(reconnectTimeout);
    if (closed === false) {
      closed = true;
      socket.close();
    }
  };

  const sign = async function (request, signatureOffset) {
    const digest = new Uint8Array(32);
    (await crypto).K12(request.subarray(HEADER_LENGTH, signatureOffset), digest, DIGEST_LENGTH);
    request.set(
      (await crypto).schnorrq.sign(await secretKey, await publicKey, digest),
      signatureOffset
    );
  };

  const send = function (request) {
    let requests = requestsByType.get(request[REQUEST_TYPE_OFFSET]);
    if (requests === undefined) {
      requests = [];
      requestsByType.set(request[REQUEST_TYPE_OFFSET], requests);
    }
    requests.push(request);

    let responses = responsesByType.get(request[REQUEST_TYPE_OFFSET]);
    if (responses === undefined) {
      responses = [];
      responsesByType.set(request[REQUEST_TYPE_OFFSET], responses);
    }
    const response = {};
    response.promise = new Promise(function (resolve) {
      response.resolve = resolve;
    });
    responses.push(response);

    socket.open.then(function () {
      socket.send(request.buffer);
    });

    return response.promise;
  };

  return {
    open,
    close,
    async getNodeInfo() {
      const length =
        HEADER_LENGTH +
        REQUEST_TYPE_LENGTH +
        REQUEST_TYPE_PADDING +
        TIMESTAMP_LENGTH +
        SIGNATURE_LENGTH;
      const request = new Uint8Array(length);
      const requestView = new DataView(request.buffer);
      requestView['setUint' + SIZE_LENGTH * 8](SIZE_OFFSET, length, true);
      requestView['setUint' + PROTOCOL_VERSION_LENGTH * 8](
        PROTOCOL_VERSION_OFFSET,
        PROTOCOL_VERSION,
        true
      );
      requestView['setUint' + REQUEST_LENGTH * 8](REQUEST_OFFSET, REQUEST, true);
      request[REQUEST_TYPE_OFFSET] = REQUEST_TYPES.GET_NODE_INFO;
      requestView.setBigUint64(TIMESTAMP_OFFSET, timestamp(), true);
      await sign(request, TIMESTAMP_OFFSET + TIMESTAMP_LENGTH);
      return send(request);
    },
    async shutdown() {
      const length =
        HEADER_LENGTH +
        REQUEST_TYPE_LENGTH +
        REQUEST_TYPE_PADDING +
        TIMESTAMP_LENGTH +
        SIGNATURE_LENGTH;
      const request = new Uint8Array(length);
      const requestView = new DataView(request.buffer);
      requestView['setUint' + SIZE_LENGTH * 8](SIZE_OFFSET, length, true);
      requestView['setUint' + PROTOCOL_VERSION_LENGTH * 8](
        PROTOCOL_VERSION_OFFSET,
        PROTOCOL_VERSION,
        true
      );
      requestView['setUint' + REQUEST_LENGTH * 8](REQUEST_OFFSET, REQUEST, true);
      request[REQUEST_TYPE_OFFSET] = REQUEST_TYPES.SHUTDOWN;
      requestView.setBigUint64(TIMESTAMP_OFFSET, timestamp(), true);
      await sign(request, TIMESTAMP_OFFSET + TIMESTAMP_LENGTH);
      send(request);
    },
  };
};
