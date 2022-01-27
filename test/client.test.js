'use strict';

import { WebSocketServer } from 'isomorphic-ws';
import { bytesToShiftedHex } from '../src/utils/hex.js';
import qubic from '../src/index.js';
import { EPOCH_LENGTH, EPOCH_OFFSET, TICK_LENGTH, TICK_OFFSET } from '../src/connection.js';
import bigInt from 'big-integer';
import getPort from 'get-port';
import rimraf from 'rimraf';
import { toString } from './utils';

const { crypto } = qubic;

jest.setTimeout(5 * 1000);

const seed = 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu';
const secretKey = [
  125, 62, 16, 133, 107, 33, 255, 186, 215, 151, 156, 9, 225, 118, 213, 175, 41, 138, 90, 128, 198,
  57, 176, 54, 161, 212, 50, 133, 236, 230, 186, 254,
];

const onconnectionSendStatus = function (epoch, tick, voidSignature) {
  return async function (socket) {
    const buffer = new ArrayBuffer(EPOCH_LENGTH + TICK_LENGTH);
    const view = new DataView(buffer);
    view.setUint32(EPOCH_OFFSET, epoch);
    view.setUint16(TICK_OFFSET, tick);

    socket.send(
      JSON.stringify({
        command: 0,
        epoch,
        tick,
        signature: voidSignature
          ? Buffer.from(new Uint8Array(64)).toString('base64')
          : Buffer.from(
              (await crypto).schnorrq.sign(
                secretKey,
                (await crypto).schnorrq.generatePublicKey(secretKey),
                Uint8Array.from(buffer)
              )
            ).toString('base64'),
      })
    );
  };
};

const onconnectionSendStatus2 = function (epoch, tick, epoch2, tick2) {
  return async function (socket) {
    const buffer = new ArrayBuffer(6);
    const view = new DataView(buffer);
    view.setUint32(EPOCH_OFFSET, epoch);
    view.setUint16(TICK_OFFSET, tick);

    socket.send(
      JSON.stringify({
        command: 0,
        epoch,
        tick,
        signature: Buffer.from(
          (await crypto).schnorrq.sign(
            secretKey,
            (await crypto).schnorrq.generatePublicKey(secretKey),
            Uint8Array.from(buffer)
          )
        ).toString('base64'),
      })
    );

    setTimeout(async function () {
      const buffer2 = new ArrayBuffer(6);
      const view2 = new DataView(buffer);
      view2.setUint32(EPOCH_OFFSET, epoch2);
      view2.setUint16(TICK_OFFSET, tick2);

      socket.send(
        JSON.stringify({
          command: 0,
          epoch: epoch2,
          tick: tick2,
          signature: Buffer.from(
            (await crypto).schnorrq.sign(
              secretKey,
              (await crypto).schnorrq.generatePublicKey(secretKey),
              Uint8Array.from(buffer2)
            )
          ).toString('base64'),
        })
      );
    }, 50);
  };
};

const onconnection = function (voidResponse) {
  let i = 0;
  return function (socket) {
    socket.on('message', function incoming(message) {
      const { command, identity, messageDigest, environmentDigest } = JSON.parse(message);

      switch (command) {
        case 1:
          socket.send(
            JSON.stringify({
              command,
              identity,
              identityNonce: voidResponse || 0,
            })
          );
          break;
        case 2:
          socket.send(
            JSON.stringify({
              command,
              identity,
              energy: '1',
            })
          );
          break;
        case 3:
          setTimeout(async function () {
            const buffer = new ArrayBuffer(EPOCH_LENGTH + TICK_LENGTH);
            const view = new DataView(buffer);
            view.setUint32(EPOCH_OFFSET, 1);
            view.setUint16(TICK_OFFSET, 2);

            socket.send(
              JSON.stringify({
                command: 0,
                epoch: 1,
                tick: 2,
                signature: Buffer.from(
                  (await crypto).schnorrq.sign(
                    secretKey,
                    (await crypto).schnorrq.generatePublicKey(secretKey),
                    Uint8Array.from(buffer)
                  )
                ).toString('base64'),
              })
            );

            setTimeout(async function () {
              socket.send(
                JSON.stringify({
                  command: 0,
                  epoch: 1,
                  tick: 2,
                  signature: Buffer.from(
                    (await crypto).schnorrq.sign(
                      secretKey,
                      (await crypto).schnorrq.generatePublicKey(secretKey),
                      Uint8Array.from(buffer)
                    )
                  ).toString('base64'),
                })
              );
            }, 1000);
          }, 1000);
          break;
        case 4:
          if (
            messageDigest === 'CCJFMKDDFJELKCLPMOCONMPFAKHPOOHNHIHCPINDBFIDLEPJHKPOOLHJPGIHJJND'
          ) {
            socket.send(
              JSON.stringify({
                command,
                messageDigest,
                reason: 'Account nonce was overwritten.',
              })
            );
          } else if (
            messageDigest === 'BLIMPJJLGFFKOOPCDMIJPCEFJCBJHDFHFKEPLNOMPBAOHFKEOOPAKKBIHDKLJIDH'
          ) {
            socket.send(
              JSON.stringify({
                command,
                messageDigest,
                inclusionState: i++ === 0 ? false : true,
                tick: 2,
                epoch: 1,
              })
            );
          } else {
            socket.send(
              JSON.stringify({
                command,
                messageDigest,
                inclusionState: messageDigest === '1' ? false : true,
                tick: 2,
                epoch: 1,
              })
            );
          }
          break;
        case 5:
          socket.send(JSON.stringify({ command, epoch: 1, tick: 1, environmentDigest, data: '' }));
          setTimeout(function () {
            socket.send(
              JSON.stringify({ command, epoch: 1, tick: 2, environmentDigest, data: '' })
            );
          }, 100);
          setTimeout(function () {
            socket.send(
              JSON.stringify({ command, epoch: 2, tick: 1, environmentDigest, data: '' })
            );
          }, 200);
          setTimeout(function () {
            socket.send(
              JSON.stringify({ command, epoch: 2, tick: 2, environmentDigest, data: '' })
            );
          }, 300);
      }
    });
  };
};

const onFaultyConnection = function (socket) {
  socket.on('message', function () {
    socket.send('test');
  });
};

const openServers = function () {
  let servers = [];
  return getPort().then(function (port0) {
    servers.push(new WebSocketServer({ port: port0 }));
    return getPort().then(function (port1) {
      servers.push(new WebSocketServer({ port: port1 }));
      return getPort().then(function (port2) {
        servers.push(new WebSocketServer({ port: port2 }));
        return {
          servers,
          ports: [port0, port1, port2],
        };
      });
    });
  });
};

const closeServers = function (servers) {
  return Promise.all(
    servers.map(function (server) {
      return new Promise(function (resolve) {
        server.close(function () {
          resolve();
        });
      });
    })
  );
};

describe('client.computors', function () {
  const client = qubic.client({
    seed,
    index: 8000,
    computors: [
      { url: 'ws://localhost:8080' },
      { url: 'ws://localhost:8081' },
      { url: 'ws://localhost:8082' },
    ],
  });
  client.onerror = function () {};

  assert({
    should: 'return list of computors',
    awaitActual: client.terminate().then(function () {
      return client.identity.then(function (identity) {
        rimraf.sync(identity);
        return client.computors();
      });
    }),
    expected: ['ws://localhost:8080', 'ws://localhost:8081', 'ws://localhost:8082'],
  });
});

describe('client.on("info", callback) (2 of 3)', function () {
  assert({
    given: '1 faulty connection',
    should: 'emit correct info',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnectionSendStatus(1, 2));
        servers[1].on('connection', onconnectionSendStatus(1, 2));
        servers[2].on('connection', onconnectionSendStatus(1, 1));

        const client = qubic.client({
          seed,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 10000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const infoArray = [];
          const infoListener = async function (info) {
            infoArray.push(info);
            if (infoArray.length === 2) {
              client.removeListener('info', infoListener);
              resolve(infoArray);
              client.terminate();
              closeServers(servers);
              rimraf.sync(await client.identity);
            }
          };
          client.addListener('info', infoListener);
        });
      });
    }),
    expected: [
      { syncStatus: 1, epoch: 1, tick: 2 },
      { syncStatus: 2, epoch: 1, tick: 2 },
    ],
  });
});

describe('client.on("info", callback) (3 of 3)', function () {
  assert({
    given: '3 correct connections',
    should: 'emit correct info',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnectionSendStatus(1, 2));
        servers[1].on('connection', onconnectionSendStatus(1, 2));
        servers[2].on('connection', onconnectionSendStatus(1, 2));

        const client = qubic.client({
          seed,
          index: 1,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 10 * 60 * 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const infoArray = [];
          const infoListener = async function (info) {
            infoArray.push(info);
            if (infoArray.length === 3) {
              resolve(infoArray);
              client.removeListener('info', infoListener);
              client.terminate();
              closeServers(servers);
              rimraf.sync(await client.identity);
            }
          };
          client.addListener('info', infoListener);
        });
      });
    }),
    expected: [
      { syncStatus: 1, epoch: 1, tick: 2 },
      { syncStatus: 2, epoch: 1, tick: 2 },
      { syncStatus: 3, epoch: 1, tick: 2 },
    ],
  });
});

describe('client.on("info", callback) (3 of 3 with 2 rounds)', function () {
  assert({
    given: '3 correct connections and 2 rounds',
    should: 'emit correct info',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnectionSendStatus2(1, 2, 1, 3));
        servers[1].on('connection', onconnectionSendStatus2(1, 2, 1, 3));
        servers[2].on('connection', onconnectionSendStatus2(1, 2, 1, 3));

        const client = qubic.client({
          seed,
          index: 2,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 10000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const infoArray = [];
          const infoListener = async function (info) {
            infoArray.push(info);
            if (infoArray.length === 6) {
              resolve(infoArray);
              client.removeListener('info', infoListener);
              client.terminate();
              closeServers(servers);
              rimraf.sync(await client.identity);
            }
          };

          client.on('info', infoListener);
        });
      });
    }),
    expected: [
      { syncStatus: 1, epoch: 1, tick: 2 },
      { syncStatus: 2, epoch: 1, tick: 2 },
      { syncStatus: 3, epoch: 1, tick: 2 },
      { syncStatus: 1, epoch: 1, tick: 3 },
      { syncStatus: 2, epoch: 1, tick: 3 },
      { syncStatus: 3, epoch: 1, tick: 3 },
    ],
  });
});

describe('client.on("info", callback) (2 of 3 with 1 invalid signature)', function () {
  assert({
    given: '1 connection with invalid signature',
    should: 'emit correct info',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnectionSendStatus(1, 2, true));
        servers[1].on('connection', onconnectionSendStatus(1, 2));
        servers[2].on('connection', onconnectionSendStatus(1, 2));

        const client = qubic.client({
          seed,
          index: 3,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 10000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const infoArray = [];
          const infoListener = async function (info) {
            infoArray.push(info);
            if (infoArray.length === 2) {
              resolve(infoArray);
              client.removeListener('info', infoListener);
              client.terminate();
              closeServers(servers);
              rimraf.sync(await client.identity);
            }
          };

          client.on('info', infoListener);
        });
      });
    }),
    expected: [
      { syncStatus: 1, epoch: 1, tick: 2 },
      { syncStatus: 2, epoch: 1, tick: 2 },
    ],
  });
});

describe('client.on("info", callback) (1 of 3)', function () {
  assert({
    given: '2 faulty connections',
    should: 'emit correct info',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnectionSendStatus(1, 2));
        servers[1].on('connection', onconnectionSendStatus(1, 1));
        servers[2].on('connection', onconnectionSendStatus(1, 0));

        const client = qubic.client({
          seed,
          index: 4,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const infoArray = [];
          const infoListener = async function (info) {
            infoArray.push(info);
            if (infoArray.length === 2) {
              resolve(infoArray[1]);
              client.removeListener('info', infoListener);
              client.terminate();
              closeServers(servers);
              rimraf.sync(await client.identity);
            }
          };

          client.on('info', infoListener);
        });
      });
    }),
    expected: { syncStatus: 0 },
  });
});

describe('client.on("info", callback) (inactive)', function () {
  assert({
    given: 'period of inactivity longer than synchronizationInterval',
    should: 'emit correct info',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnectionSendStatus(1, 2));
        servers[1].on('connection', onconnectionSendStatus(1, 2));
        servers[2].on('connection', onconnectionSendStatus(1, 2));

        const client = qubic.client({
          seed,
          index: 5,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const infoArray = [];
          const infoListener = async function (info) {
            infoArray.push(info);
            if (infoArray.length === 4) {
              resolve(infoArray);
              client.removeListener('info', infoListener);
              client.terminate();
              closeServers(servers);
              rimraf.sync(await client.identity);
            }
          };

          client.on('info', infoListener);
        });
      });
    }),
    expected: [
      { syncStatus: 1, epoch: 1, tick: 2 },
      { syncStatus: 2, epoch: 1, tick: 2 },
      { syncStatus: 3, epoch: 1, tick: 2 },
      { syncStatus: 0 },
    ],
  });
});

describe('client.sendCommand - 1 = fetch identityNonce (2 of 3)', function () {
  assert({
    given: '1 faulty connection',
    should: 'resolve with correct identityNonce',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onconnection(true));
        servers[2].on('connection', onconnection());

        const client = qubic.client({
          seed,
          index: 6,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return client.sendCommand(1, { identity: '1' }).then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: { command: 1, identity: '1', identityNonce: 0 },
  });
});

describe('client.sendCommand - 1 = fetch identityNonce (1 of 3)', function () {
  assert({
    given: '3 faulty connections',
    should: 'reject with error',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onconnection(1));
        servers[2].on('connection', onconnection(2));

        const client = qubic.client({
          seed,
          index: 7,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return toString(Try(client.sendCommand, 1, { identity: '1' })).then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: 'Invalid responses.',
  });
});

describe('client.sendCommand - 1 = fetch identityNonce (2 of 3 with reconnect)', function () {
  assert({
    given: '1 faulty connection',
    should: 'resolve with correct result',
    awaitActual: crypto.then(function ({ schnorrq }) {
      let servers = [];
      return Promise.all([getPort(), getPort(), getPort()])
        .then(function (ports) {
          servers.push(new WebSocketServer({ port: ports[0] }));
          return {
            servers,
            ports,
          };
        })
        .then(function ({ servers, ports }) {
          servers[0].on('connection', onconnection());

          const client = qubic.client({
            seed,
            index: 8,
            computors: [
              { url: 'ws://localhost:' + ports[0].toString() },
              { url: 'ws://localhost:' + ports[1].toString() },
              { url: 'ws://localhost:' + ports[2].toString() },
            ],
            synchronizationInterval: 1000,
            adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
          });
          client.on('error', function () {});

          const actual = client.sendCommand(1, { identity: '1' });

          setTimeout(function () {
            servers.push(new WebSocketServer({ port: ports[1] }));
            servers.push(new WebSocketServer({ port: ports[2] }));
            servers[1].on('connection', onconnection(1));
            servers[2].on('connection', onconnection());
          }, 2000);
          return actual.then(function (actual) {
            client.terminate();
            closeServers(servers);
            client.identity.then(rimraf.sync);
            return actual;
          });
        });
    }),
    expected: { command: 1, identity: '1', identityNonce: 0 },
  });
});

describe('client.sendCommand - 1 = fetch identityNonce (2 of 3 with double call)', function () {
  assert({
    given: '1 faulty connection',
    should: 'resolve with correct result',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onconnection(1));

        const client = qubic.client({
          seed,
          index: 9,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        client.sendCommand(0, { identity: '1' });
        servers[2].on('connection', onconnection());

        return client.sendCommand(1, { identity: '1' }).then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: { command: 1, identity: '1', identityNonce: 0 },
  });
});

describe('client.sendCommand - 1 = fetch identityNonce (2 of 3 with faulty connection)', function () {
  assert({
    given: '1 faulty connection',
    should: 'resolve with correct result',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onFaultyConnection);
        servers[2].on('connection', onconnection());

        const client = qubic.client({
          seed,
          index: 10,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return client.sendCommand(1, { identity: '1' }).then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: { command: 1, identity: '1', identityNonce: 0 },
  });
});

describe('client.sendCommand - 2 = fetch energy (2 of 3)', function () {
  assert({
    given: '1 faulty connection',
    should: 'resolve with correct energy',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onconnection(1));
        servers[2].on('connection', onconnection());

        const client = qubic.client({
          seed,
          index: 11,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return client.sendCommand(2, { identity: '1' }).then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: { command: 2, identity: '1', energy: '1' },
  });
});

describe('client.transaction, client.sendCommand - 3 = send transfer', function () {
  const clientAndServers = crypto.then(function ({ schnorrq }) {
    return openServers().then(function ({ servers, ports }) {
      servers[0].on('connection', onconnection());
      servers[1].on('connection', onconnection(1));
      servers[2].on('connection', onconnection());
      return [
        qubic.client({
          seed,
          index: 1337,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 10000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        }),
        servers,
      ];
    });
  });

  assert({
    given: '1 faulty connection',
    should: 'resolve with correct transfer',
    awaitActual: clientAndServers.then(function ([client]) {
      client.on('error', function () {});
      return client.transaction({
        recipientIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
        energy: bigInt(1),
      });
    }),
    expected: {
      messageDigest: 'BLIMPJJLGFFKOOPCDMIJPCEFJCBJHDFHFKEPLNOMPBAOHFKEOOPAKKBIHDKLJIDH',
      message:
        'MslsS88eki5QgskhpN3vSSuPGqo6s+ylH+V1tge9BcoAAAAAAQAAAAAAAAAyyWxLzx6SLlCCySGk3e9JK48aqjqz7KUf5XW2B70Fyg==',
      signature:
        'xoe0T0EUtCrIG7W5XlFSXKxNT3E+XxqYSWHzUId8Fawm9R+yTLP9NSFwN6l56GnCABl6sq6p5nVM06RSzoEgAA==',
    },
  });

  assert({
    given: '1 faulty connection',
    should: 'emit correct transfer inclusion state',
    awaitActual: clientAndServers.then(function ([client]) {
      return new Promise(function (resolve) {
        client.addListener('inclusion', function (event) {
          resolve(event);
        });
      });
    }),
    expected: {
      messageDigest: 'BLIMPJJLGFFKOOPCDMIJPCEFJCBJHDFHFKEPLNOMPBAOHFKEOOPAKKBIHDKLJIDH',
      inclusionState: true,
      tick: 2,
      epoch: 1,
    },
  });

  clientAndServers.then(function ([client]) {
    client.transaction({
      recipientIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
      energy: bigInt(0),
    });
  });

  assert({
    given: 'that account nonce was overwritten',
    should: 'reject with reason',
    awaitActual: clientAndServers.then(function ([client]) {
      return new Promise(function (resolve) {
        client.addListener('rejection', function (event) {
          resolve(event);
        });
      });
    }),
    expected: {
      messageDigest: 'CCJFMKDDFJELKCLPMOCONMPFAKHPOOHNHIHCPINDBFIDLEPJHKPOOLHJPGIHJJND',
      reason: 'Account nonce was overwritten.',
    },
  });

  assert({
    given: 'insufficient energy',
    should: 'reject with correct error',
    awaitActual: clientAndServers.then(function ([client]) {
      client.on('error', function () {});
      return toString(
        Try(client.transaction, {
          recipientIdentity:
            'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
          energy: bigInt(10000000),
        })
      );
    }),
    expected: 'Error: Insufficient energy.',
  });

  afterAll(function () {
    clientAndServers.then(function ([client, servers]) {
      client.terminate();
      closeServers(servers);
      client.identity.then(rimraf.sync);
    });
  });
});

describe('client.transaction (send effect)', function () {
  const clientAndServers = crypto.then(function ({ schnorrq }) {
    return openServers().then(function ({ servers, ports }) {
      servers[0].on('connection', onconnection());
      servers[1].on('connection', onconnection(1));
      servers[2].on('connection', onconnection());
      return [
        qubic.client({
          seed,
          index: 1338,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 10000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        }),
        servers,
      ];
    });
  });

  assert({
    given: 'effect payload',
    should: 'resolve with correct transaction',
    awaitActual: clientAndServers.then(function ([client]) {
      return client.transaction({
        effectPayload: new Uint8Array(10).fill(1),
      });
    }),
    expected: {
      messageDigest: 'MGHOIOGNIGCJJAOOBCPKMJLIGGNIGDLHHLEJOFEJCBOKDLNAONBEFJDBAPCHGEFD',
      message:
        'oa9OKe9epqF9d2p97FZCBMDkGpAWKSEjfHt6fLp+8soAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQE=',
      signature:
        'fXll7vTIuaPvxuIr0eyQbELdjWP9oI+jIDDwbXKPBnSQVBjypBGlapJfIligClx35nEUG5XRH0GjHVQCmKEkAA==',
    },
  });

  afterAll(function () {
    clientAndServers.then(function ([client, servers]) {
      client.terminate();
      closeServers(servers);
      client.identity.then(rimraf.sync);
    });
  });
});

describe('client.sendCommand - 4 = fetch transfer status (2 of 3)', function () {
  assert({
    given: '1 faulty connection',
    should: 'resolve with correct transfer status',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onconnection(1));
        servers[2].on('connection', onconnection());

        const client = qubic.client({
          seed,
          index: 12,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return client.sendCommand(4, { messageDigest: '1' }).then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: { command: 4, messageDigest: '1', inclusionState: false, tick: 2, epoch: 1 },
  });
});

describe('client.sendCommand - 4 = fetch transfer status (2 of 3 with relaunch)', function () {
  assert({
    given: '1 faulty connection and a relaunch',
    should: 'resolve with correct transfer status',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        const client = qubic.client({
          seed,
          index: 13,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return client
          .terminate()
          .then(client.launch)
          .then(function () {
            servers[0].on('connection', onconnection());
            servers[1].on('connection', onconnection(1));
            servers[2].on('connection', onconnection());

            return client.sendCommand(4, { messageDigest: '2' }).then(function (actual) {
              client.terminate();
              closeServers(servers);
              client.identity.then(rimraf.sync);
              return actual;
            });
          });
      });
    }),
    expected: { command: 4, messageDigest: '2', inclusionState: true, tick: 2, epoch: 1 },
  });
});

describe('client.addEnvironmentListener/removeEnvironmentListener', function () {
  assert({
    given: 'a subscription',
    should: 'emit correct events',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        servers[0].on('connection', onconnection());
        servers[1].on('connection', onconnection());
        servers[2].on('connection', onconnection());
        const client = qubic.client({
          seed,
          index: 14,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        return new Promise(function (resolve) {
          const data = [];
          const listener2 = function () {};
          const listener = function (value) {
            data.push(value);
            if (data.length === 3) {
              client.removeEnvironmentListener('H', listener);
              client.removeEnvironmentListener('H', listener2);
            }
          };
          client.addEnvironmentListener('H', listener);
          client.addEnvironmentListener('H', listener2);
          client.sendCommand(5, { environmentDigest: 'H' });
          setTimeout(function () {
            resolve(data);
          }, 1000);
        }).then(function (result) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return result;
        });
      });
    }),
    expected: [
      {
        environmentDigest: 'H',
        epoch: 1,
        tick: 1,
        data: '',
      },
      {
        environmentDigest: 'H',
        epoch: 1,
        tick: 2,
        data: '',
      },
      {
        environmentDigest: 'H',
        epoch: 2,
        tick: 1,
        data: '',
      },
    ],
  });
});

describe('client.setComputorUrl', function () {
  assert({
    given: 'computor urls',
    should: 'reopen connections',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        const client = qubic.client({
          seed,
          index: 15,
          computors: [
            { url: 'ws://localhost' },
            { url: 'ws://localhost' },
            { url: 'ws://localhost' },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});

        servers[0].on('connection', onconnection());
        servers[1].on('connection', onFaultyConnection);
        servers[2].on('connection', onconnection());

        client.setComputorUrl(0, 'ws://localhost:' + ports[0].toString());
        client.setComputorUrl(1, 'ws://localhost:' + ports[1].toString());
        client.setComputorUrl(2, 'ws://localhost:' + ports[2].toString());

        const actual = client.sendCommand(1, { identity: '1' });

        return actual.then(function (actual) {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return actual;
        });
      });
    }),
    expected: { command: 1, identity: '1', identityNonce: 0 },
  });
});

describe('client.setComputorUrl', function () {
  assert({
    given: 'url that we have connected to already',
    should: 'not reopen connection',
    awaitActual: crypto.then(function ({ schnorrq }) {
      return openServers().then(function ({ servers, ports }) {
        const client = qubic.client({
          seed,
          index: 16,
          computors: [
            { url: 'ws://localhost:' + ports[0].toString() },
            { url: 'ws://localhost:' + ports[1].toString() },
            { url: 'ws://localhost:' + ports[2].toString() },
          ],
          synchronizationInterval: 1000,
          adminPublicKey: bytesToShiftedHex(schnorrq.generatePublicKey(secretKey)),
        });
        client.on('error', function () {});
        client.terminate({ closeConnection: false });

        servers[0].on('connection', onconnection());
        servers[1].on('connection', onFaultyConnection);
        servers[2].on('connection', onconnection());

        let closed = false;
        client.on('close', function () {
          closed = true;
        });

        client.setComputorUrl(0, 'ws://localhost:' + ports[0].toString());

        return client.sendCommand(1, { identity: '1' }).then(function () {
          client.terminate();
          closeServers(servers);
          client.identity.then(rimraf.sync);
          return closed;
        });
      });
    }),
    expected: false,
  });
});
