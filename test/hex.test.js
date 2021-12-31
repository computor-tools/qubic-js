import { hexToBytes, shiftedHexToBytes, bytesToShiftedHex } from '../src/utils/hex';

describe('hexToBytes', function () {
  assert({
    given: 'hex',
    should: 'return correct bytes',
    actual: hexToBytes('1f'),
    expected: new Uint8Array([31]),
  });
});

describe('shiftedHexToBytes, bytesToShiftedHex', function () {
  assert({
    given: 'hex',
    should: 'covnert to hex and back',
    actual: bytesToShiftedHex(shiftedHexToBytes('f')),
    expected: 'af',
  });
});
