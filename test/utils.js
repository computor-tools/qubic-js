'use strict';

export const toString = function (x) {
  return x.then(function (y) {
    return y.toString();
  });
};
