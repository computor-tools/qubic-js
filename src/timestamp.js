let t;

export const timestamp = function () {
  const date = new Date();
  let ts =
    ((((((BigInt(date.getUTCFullYear() - 2001) * 12n + BigInt(date.getUTCMonth())) * 31n +
      BigInt(date.getUTCDate() - 1)) *
      24n +
      BigInt(date.getUTCHours())) *
      60n +
      BigInt(date.getUTCMinutes())) *
      60n +
      BigInt(date.getUTCSeconds())) *
      1000n +
      BigInt(date.getUTCMilliseconds())) *
    1000000n;

  if (t === undefined) {
    t = ts;
  } else if (t >= ts) {
    if (t > ts) {
      ts = t;
    }
    if (t === ts) {
      ts += 1000000n;
    }
  }

  t = ts;
  return ts;
};
