'use strict';

import {
  createIdentity,
  verifyChecksum,
  seedChecksum,
  SEED_IN_LOWERCASE_LATIN_LENGTH,
} from '../src/identity.js';
import { toString } from './utils.js';

describe('createIdentity', function () {
  assert({
    given: 'seed & index',
    should: 'resolve with correct identity',
    awaitActual: createIdentity('vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu', 1337),
    expected: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
  });

  assert({
    given: 'invalid seed',
    should: 'reject with correct error',
    awaitActual: toString(
      Try(createIdentity, 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevre', 0)
    ),
    expected: 'Error: Invalid seed. Must be 55 lowercase latin chars.',
  });

  assert({
    given: 'illegal index',
    should: 'reject with correct error',
    awaitActual: toString(
      Try(createIdentity, 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu', '1')
    ),
    expected: 'Error: Illegal index.',
  });

  assert({
    given: 'illegal index (negative)',
    should: 'reject with correct error',
    awaitActual: toString(
      Try(createIdentity, 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu', -1)
    ),
    expected: 'Error: Illegal index.',
  });
});

describe('verifyChecksum', function () {
  assert({
    given: 'identity with correct checksum',
    should: 'return true',
    awaitActual: verifyChecksum(
      'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE'
    ),
    expected: true,
  });
  assert({
    given: 'identity with invalid checksum',
    should: 'return false',
    awaitActual: verifyChecksum(
      'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAF'
    ),
    expected: false,
  });
});

describe('seedChecksum', function () {
  assert({
    given: 'seed',
    should: 'return correct checksum',
    awaitActual: seedChecksum('a'.repeat(SEED_IN_LOWERCASE_LATIN_LENGTH)),
    expected: 'EEF',
  });
});
