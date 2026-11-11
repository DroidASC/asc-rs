// What newer compilers have forms of their own for: sendable classes,
// concurrent functions, static blocks, private methods, top-level await,
// big integers, operators the other files leave out.
class Shared {
  count: number = 0;
  constructor() {
    'use sendable';
  }
  bump(): number {
    return ++this.count;
  }
}

function work(input: number): number {
  'use concurrent';
  return input * 2;
}

class Vault {
  static opened = 0;
  static {
    Vault.opened = 1;
  }
  #secret = 0x1fn;
  #mix(by: bigint): bigint {
    return this.#secret ** by;
  }
  static audit(vault: Vault): boolean {
    return vault instanceof Vault;
  }
  open(by: bigint): bigint {
    Vault.opened++;
    return Vault.audit(this) ? this.#mix(by) : -1n;
  }
  get [`dyn${1}`](): number {
    return Vault.opened;
  }
  set value(next: number) {
    Vault.opened = next & 0xff;
  }
}

class Base {
  greet(): string {
    return 'base';
  }
  static create(): Base {
    return new this();
  }
}

class Derived extends Base {
  constructor(...args: number[]) {
    super(...(args as []));
  }
  greet(): string {
    const up = () => super.greet();
    return up() + super['greet']() + new.target;
  }
  static create(): Derived {
    return super.create() as Derived;
  }
}

function tag(strings: TemplateStringsArray, ...values: number[]): string {
  return strings.raw.join('|') + values.length;
}

function many(): number {
  let a0 = 0, a1 = 1, a2 = 2, a3 = 3, a4 = 4, a5 = 5, a6 = 6, a7 = 7, a8 = 8, a9 = 9;
  let b0 = 0, b1 = 1, b2 = 2, b3 = 3, b4 = 4, b5 = 5, b6 = 6, b7 = 7, b8 = 8, b9 = 9;
  const read = () => a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + b0 + b1 + b2 + b3 + b4 + b5 + b6 + b7 + b8 + b9;
  const write = () => { a9 = b9 = 1; return function inner() { return a9 + b0; }; };
  return read() + write()();
}

function ops(a: number, b: number, o: any): unknown[] {
  let i = 10;
  i--;
  const key = 'k' + a;
  o[key] = a / b;
  o[3] = a >= b;
  o.deep = { [key]: a <= b, ...o, get g() { return 1; }, set s(v: number) {} };
  delete o.deep[key];
  return [a & b, a >> b, ~a, !a, -a, +o, typeof o, o?.deep?.[key], o.deep ??= 1, a != b, a !== b, o[0], void 0, [...o.list, a], Symbol.iterator in o, i];
}

const settled = await Promise.resolve(new Shared().bump() + work(2));
const objects = [new Vault().open(2n), Derived.create().greet(), tag`a${1}b${2}`, many(), ops(6, 3, { list: [] }), settled];
export default objects;
globalThis.leak = objects.length;
