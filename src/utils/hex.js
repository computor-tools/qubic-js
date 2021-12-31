'use strict';

export const HEX_CHARS_PER_BYTE = 2;
const HEX_BASE = 16;
const SHIFTED_HEX_CHARS = 'abcdefghijklmnop';
const HEX_CHARS = '0123456789abcdef';

export const shiftedHexToBytes = function (hex) {
  if (hex.length % HEX_CHARS_PER_BYTE !== 0) {
    hex = 'a' + hex;
  }

  const bytes = new Uint8Array(hex.length / HEX_CHARS_PER_BYTE);
  for (let i = 0, c = 0; c < hex.length; c += HEX_CHARS_PER_BYTE) {
    bytes[i++] = parseInt(
      hex
        .substr(c, HEX_CHARS_PER_BYTE)
        .split('')
        .map(function (char) {
          return HEX_CHARS[SHIFTED_HEX_CHARS.indexOf(char)];
        })
        .join(''),
      HEX_BASE
    );
  }
  return bytes;
};

export const bytesToShiftedHex = function (bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += SHIFTED_HEX_CHARS[bytes[i] >> 4] + SHIFTED_HEX_CHARS[bytes[i] & 15];
  }
  return hex;
};

export const hexToBytes = function (hex) {
  if (hex.length % HEX_CHARS_PER_BYTE !== 0) {
    hex = '0' + hex;
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};
