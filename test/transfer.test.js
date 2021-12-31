'use strict';

import bigInt from 'big-integer';
import { createTransfer } from '../src/transfer.js';
import { shiftedHexToBytes } from '../src/utils/hex.js';
import { crypto } from '../src/index.js';
import { PUBLIC_KEY_LENGTH_IN_HEX } from '../src/identity.js';
import { toString } from './utils.js';

describe('createTransfer', function () {
  const transfer = {
    seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
    from: {
      identity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
      index: 1337,
      identityNonce: 0,
      energy: bigInt(2),
    },
    to: {
      identity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
      energy: bigInt(1),
    },
  };

  assert({
    given: 'valid arguments',
    should: 'resolve with correct message and signature',
    awaitActual: createTransfer(transfer).then(function (actual) {
      return crypto.then(function ({ schnorrq }) {
        actual.isValidSignature = schnorrq.verify(
          shiftedHexToBytes(
            transfer.from.identity.slice(0, PUBLIC_KEY_LENGTH_IN_HEX).toLowerCase()
          ),
          Uint8Array.from(Buffer.from(actual.message, 'base64')),
          Uint8Array.from(Buffer.from(actual.signature, 'base64'))
        );
        return actual;
      });
    }),
    expected: {
      hash: 'JJBGCAODHCGCLMPEMAMFHAIAIFGNPBFKNFLGIAJNIODILMGPHPACFDGFODHEAMJL',
      message:
        'MslsS88eki5QgskhpN3vSSuPGqo6s+ylH+V1tge9BcoAAAAAMslsS88eki5QgskhpN3vSSuPGqo6s+ylH+V1tge9BcoB',
      signature:
        'ZhLgXQXH9JyMMekNaM+4A1c0b21cWMZhfkITReMuK8w7a+vI8wOpFCha0DuTjErUQDI3iC9MUlx519RxSKEKAA==',
      isValidSignature: 1,
    },
  });

  assert({
    given: 'sender identity with invalid checksum',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        from: {
          ...transfer.from,
          identity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
        },
      })
    ),
    expected:
      'Error: Invalid checksum: DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
  });

  assert({
    given: 'recipient identity with invalid checksum',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        to: {
          ...transfer.to,
          identity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
        },
      })
    ),
    expected:
      'Error: Invalid checksum: DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF',
  });

  assert({
    given: 'illegal index (float)',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        from: {
          ...transfer.from,
          index: 0.5,
        },
      })
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal index (string)',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        from: {
          ...transfer.from,
          index: '0',
        },
      })
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal index (negative)',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        from: {
          ...transfer.from,
          index: -1,
        },
      })
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal nonce',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        from: {
          ...transfer.from,
          identityNonce: '1',
        },
      })
    ),
    expected: 'Error: Illegal nonce.',
  });

  assert({
    given: 'illegal sender energy',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        from: {
          ...transfer.from,
          energy: 1,
        },
      })
    ),
    expected: 'Error: Illegal energy.',
  });

  assert({
    given: 'illegal recipient energy',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        to: {
          ...transfer.to,
          energy: 1,
        },
      })
    ),
    expected: 'Error: Illegal energy.',
  });

  assert({
    given: 'insufficient sender energy',
    should: 'throw error',
    awaitActual: toString(
      Try(createTransfer, {
        ...transfer,
        to: {
          ...transfer.to,
          energy: bigInt(3),
        },
      })
    ),
    expected: 'Error: Insufficient energy.',
  });
});
