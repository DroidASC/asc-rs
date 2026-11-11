// A module that exports in every way.
export const VERSION = '1.2.3';
export let hits = 0;
export function touch(): number {
  return ++hits;
}
export default class Registry<T> {
  private items = new Map<string, T>();
  add(key: string, item: T): this {
    this.items.set(key, item);
    return this;
  }
  get(key: string): T | undefined {
    return this.items.get(key);
  }
}
function hidden(): string {
  return 'hidden';
}
export { hidden as visible };
export * from './other';
export * as others from './other';
export { thing as renamed } from './other';
export interface Named { name: string }
export type Id = string | number;
export namespace Tools {
  export const sharp = true;
  export function cut(text: string, at: number): string[] {
    return [text.slice(0, at), text.slice(at)];
  }
}
