// A module that imports in every way.
import Registry, { VERSION, touch, visible as shown, hits } from './lib';
import * as lib from './lib';
import { thing } from './other';
import type { Named } from './lib';
import './other';

const registry = new Registry<Named>();
registry.add('a', { name: 'A' }).add('b', { name: 'B' });

async function lazy(): Promise<number> {
  const other = await import('./other');
  return other.thing + touch() + hits;
}

function report(): string {
  return [VERSION, shown(), lib.Tools.cut('abcdef', 3).join('|'), String(thing), registry.get('a')?.name].join(' ');
}

print(report(), lazy(), lib.others, typeof lib.default);
