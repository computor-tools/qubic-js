'use strict';

import bigInt from 'big-integer';
import { transaction } from '../src/transaction.js';
import { shiftedHexToBytes } from '../src/utils/hex.js';
import { crypto } from '../src/index.js';
import { createIdentity, PUBLIC_KEY_LENGTH_IN_HEX } from '../src/identity.js';
import { toString } from './utils.js';

describe('transaction', function () {
  const transfer = {
    seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
    index: 1337,
    senderIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
    identityNonce: 0,
    recipientIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
    energy: bigInt(1),
  };

  assert({
    given: 'valid arguments',
    should: 'resolve with correct message and signature',
    awaitActual: transaction(transfer).then(function (actual) {
      return crypto.then(function ({ schnorrq }) {
        return {
          ...actual,
          isValidSignature: schnorrq.verify(
            shiftedHexToBytes(
              transfer.senderIdentity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()
            ),
            Uint8Array.from(shiftedHexToBytes(actual.messageDigest.toLowerCase())),
            Uint8Array.from(Buffer.from(actual.signature, 'base64'))
          ),
        };
      });
    }),
    expected: {
      messageDigest: 'BLIMPJJLGFFKOOPCDMIJPCEFJCBJHDFHFKEPLNOMPBAOHFKEOOPAKKBIHDKLJIDH',
      message:
        'MslsS88eki5QgskhpN3vSSuPGqo6s+ylH+V1tge9BcoAAAAAAQAAAAAAAAAyyWxLzx6SLlCCySGk3e9JK48aqjqz7KUf5XW2B70Fyg==',
      signature:
        'xoe0T0EUtCrIG7W5XlFSXKxNT3E+XxqYSWHzUId8Fawm9R+yTLP9NSFwN6l56GnCABl6sq6p5nVM06RSzoEgAA==',
      isValidSignature: 1,
    },
  });

  assert({
    given: 'valid arguments (overwritting identity nonce)',
    should: 'resolve with correct message and signature',
    awaitActual: transaction({ ...transfer, recipientIdentity: undefined, energy: bigInt(0) }).then(
      function (actual) {
        return crypto.then(function ({ schnorrq }) {
          return {
            ...actual,
            isValidSignature: schnorrq.verify(
              shiftedHexToBytes(
                transfer.senderIdentity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()
              ),
              Uint8Array.from(shiftedHexToBytes(actual.messageDigest.toLowerCase())),
              Uint8Array.from(Buffer.from(actual.signature, 'base64'))
            ),
          };
        });
      }
    ),
    expected: {
      messageDigest: 'LBMMJINBHHNEOFLLNHMJEEKBLGPMMHMJNGHMKFNPINNGHGHAHFEEHFNPJMOEGJJK',
      message:
        'MslsS88eki5QgskhpN3vSSuPGqo6s+ylH+V1tge9BcoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
      signature:
        'RxyDP+wjtNXCBt5zIEkgR7mR+jzlYwW413gqhRiIxzu0OZlQa45OWqto2BaNG7eJnOcXBlm5gYAJJQWo7YMTAA==',
      isValidSignature: 1,
    },
  });

  assert({
    given: 'valid arguments (index=undefined)',
    should: 'resolve with correct message and signature',
    awaitActual: createIdentity(transfer.seed, 0)
      .then(function (senderIdentity) {
        return transaction({
          ...transfer,
          senderIdentity,
          index: undefined,
        }).then(function (actual) {
          return [actual, senderIdentity];
        });
      })
      .then(function ([actual, senderIdentity]) {
        return crypto.then(function ({ schnorrq }) {
          return {
            ...actual,
            isValidSignature: schnorrq.verify(
              shiftedHexToBytes(senderIdentity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()),
              Uint8Array.from(shiftedHexToBytes(actual.messageDigest.toLowerCase())),
              Uint8Array.from(Buffer.from(actual.signature, 'base64'))
            ),
          };
        });
      }),
    expected: {
      messageDigest: 'IHGMGILJMNALGPHCKDLEPAKFHKAOMFGHJAINJDGOBBHLLKHBALDLNGBEAKIAAEDC',
      message:
        'AkhiNxR8LsCpGHe1KjlRdANz0oxVlWt+qbaorpGoUi4AAAAAAQAAAAAAAAAyyWxLzx6SLlCCySGk3e9JK48aqjqz7KUf5XW2B70Fyg==',
      signature:
        'ivcvJzYHPPm9c7j6VmWbYNn1uigTUdMhrjEd9Z7u5kRxc6fnoC/smgb2c38wrs6WaTvwLF9TSGL7DYu7e9wOAA==',
      isValidSignature: 1,
    },
  });

  assert({
    given: 'valid arguments (with effect payload)',
    should: 'resolve with correct message and signature',
    awaitActual: transaction({ ...transfer, effectPayload: new Uint8Array(10).fill(1) }).then(
      function (actual) {
        return crypto.then(function ({ schnorrq }) {
          return {
            ...actual,
            isValidSignature: schnorrq.verify(
              shiftedHexToBytes(
                transfer.senderIdentity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()
              ),
              Uint8Array.from(shiftedHexToBytes(actual.messageDigest.toLowerCase())),
              Uint8Array.from(Buffer.from(actual.signature, 'base64'))
            ),
          };
        });
      }
    ),
    expected: {
      messageDigest: 'CIFGEHDEGFLNBPOFAHDOGIPBHOFECDJOCEGAOPFFKHNEJGBAHGADELKCDFEDPBIA',
      message:
        'MslsS88eki5QgskhpN3vSSuPGqo6s+ylH+V1tge9BcoAAAAAAQAAAAAAAAAyyWxLzx6SLlCCySGk3e9JK48aqjqz7KUf5XW2B70FygEBAQEBAQEBAQE=',
      signature:
        'fh8P3wolsp+DOKhJCAsWRh7oEwblIT9orX0CSmvGMMGrtU/70myURxQ3Y5cWGwtBjQJ2rreGKQeySqN1mfcEAA==',
      isValidSignature: 1,
    },
  });

  assert({
    given: 'sender identity with invalid checksum',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        senderIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
      })
    ),
    expected:
      'Error: Invalid checksum: DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
  });

  assert({
    given: 'recipient identity with invalid checksum',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        recipientIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
      })
    ),
    expected:
      'Error: Invalid checksum: DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
  });

  assert({
    given: 'illegal index (float)',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        index: 0.5,
      })
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal index (string)',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        index: '0',
      })
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal index (negative)',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        index: -1,
      })
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal nonce',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        identityNonce: '1',
      })
    ),
    expected: 'Error: Illegal identity nonce.',
  });

  assert({
    given: 'illegal energy',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        energy: 1,
      })
    ),
    expected: 'Error: Illegal energy.',
  });

  assert({
    given: 'sender identity with invalid checksum',
    should: 'throw error',
    awaitActual: toString(
      Try(transaction, {
        ...transfer,
        effectPayload: 'test',
      })
    ),
    expected: 'Error: Illegal effect payload.',
  });
});
