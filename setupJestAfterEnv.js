global.assert = async function ({ given = '', should = '', actual, awaitActual, expected }) {
  global.test(`Given ${given}: should ${should}`, async function () {
    global
      .expect(awaitActual && typeof awaitActual.then === 'function' ? await awaitActual : actual)
      .toStrictEqual(expected);
  });
};

global.Try = async function (f, ...args) {
  try {
    let x = f(...args);
    return x && typeof x.then === 'function'
      ? x.catch(function (y) {
          return y;
        })
      : x;
  } catch (error) {
    return error;
  }
};
