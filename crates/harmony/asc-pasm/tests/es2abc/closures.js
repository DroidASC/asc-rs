// Closures, lexical environments, literal arrays and objects, destructuring.
function counter(start) {
  let value = start;
  const history = [];
  return {
    next() {
      history.push(value);
      return value++;
    },
    reset: () => {
      value = start;
      history.length = 0;
    },
    get seen() {
      return history.slice();
    },
  };
}

function curry(f) {
  return function (a) {
    return function (b) {
      return function (c) {
        return f(a, b, c);
      };
    };
  };
}

var table = [1, 2.5, -3, 'four', true, null, undefined, [5, 6, [7]], { eight: 8, 'nine nine': 9n }];
var config = { name: 'cfg', depth: 3, ratio: 0.25, flags: [true, false], nested: { a: 1, b: 'two' }, 0: 'zero' };
var big = [0x7fffffff, -0x80000000, 4294967296, 1e300, -0.0, 65536, 255, 256];
var { name, depth = 1, ...others } = config;
var [first, , third = 30, ...tail] = table;
var template = `${name}:${depth}:${first + third}`;
var regex = /a(b+)c/gi;

const counters = [];
for (let i = 0; i < 3; i++) {
  counters.push(() => i * 2);
}
label: for (var j = 0; j < 10; j++) {
  for (var k in config) {
    if (k === 'depth') continue label;
    if (j > 5) break label;
  }
}
var c = counter(10);
c.next();
var sum = curry((a, b, c) => a + b + c)(1)(2)(3);
print(c.seen, sum, template, regex.test('abbc'), tail.length, others, big, counters.map((f) => f()));
do { sum >>>= 1; sum ^= 3; sum |= 0; } while (sum > 100 && !(sum % 7 == 0));
var cond = sum ? (sum << 2) : void 0;
with_spread(...table);
function with_spread() { return arguments.length + [...arguments].length + (new.target === undefined ? 0 : 1); }
