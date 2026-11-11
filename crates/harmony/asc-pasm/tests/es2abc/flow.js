// async, generators, try / catch / finally, typed catches by instanceof.
async function fetchAll(urls) {
  const results = [];
  for (const url of urls) {
    try {
      const reply = await request(url);
      results.push(reply);
    } catch (error) {
      if (error instanceof RangeError) {
        results.push(null);
      } else {
        throw error;
      }
    } finally {
      print('done', url);
    }
  }
  return results;
}

function request(url) {
  return new Promise((resolve, reject) => {
    if (url.length > 64) reject(new RangeError('too long'));
    else resolve({ url, status: 200 });
  });
}

function* range(from, to, step = 1) {
  for (let i = from; i < to; i += step) {
    const sent = yield i;
    if (sent === 'stop') return -1;
  }
  yield* [to, to + 1];
}

async function* ticks(n) {
  for (let i = 0; i < n; i++) {
    yield await Promise.resolve(i);
  }
}

async function consume() {
  let total = 0;
  for await (const tick of ticks(3)) {
    total += tick;
  }
  return total;
}

function nested(depth) {
  try {
    try {
      if (depth > 2) throw new Error('deep');
      return depth;
    } finally {
      depth++;
    }
  } catch ({ message }) {
    return message.length;
  }
}

const arrow = async (x) => (await x) ?? 'none';
fetchAll(['a', 'b']).then((all) => print(all.length), print);
print([...range(0, 5, 2)], nested(3), consume(), arrow(null), 2 ** 10, 7 % 3, 'k' in { k: 1 });
