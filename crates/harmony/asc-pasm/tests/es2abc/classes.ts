// Classes, inheritance, accessors, static members, private fields.
export class Shape {
  static count: number = 0;
  #id: number;
  protected name: string;
  constructor(name: string) {
    this.name = name;
    this.#id = Shape.count++;
  }
  get id(): number {
    return this.#id;
  }
  set label(value: string) {
    this.name = value;
  }
  area(): number {
    return 0;
  }
  describe(): string {
    return `${this.name}#${this.#id}: ${this.area()}`;
  }
  static make(kind: string, ...sizes: number[]): Shape {
    switch (kind) {
      case 'circle':
        return new Circle(sizes[0]);
      case 'rect':
        return new Rect(sizes[0], sizes[1] ?? sizes[0]);
      default:
        throw new TypeError('unknown shape ' + kind);
    }
  }
}

export class Circle extends Shape {
  constructor(private radius: number) {
    super('circle');
  }
  area(): number {
    return Math.PI * this.radius ** 2;
  }
  describe(): string {
    return super.describe() + ' (round)';
  }
}

class Rect extends Shape {
  width: number;
  height: number;
  constructor(width: number, height: number) {
    super('rect');
    this.width = width;
    this.height = height;
  }
  area(): number {
    return this.width * this.height;
  }
  get [Symbol.toStringTag](): string {
    return 'Rect';
  }
}

enum Color { Red, Green = 4, Blue }

export function total(shapes: Shape[]): number {
  let sum = 0;
  for (const shape of shapes) {
    sum += shape.area();
  }
  return sum + Color.Blue;
}

const shapes = [Shape.make('circle', 1), Shape.make('rect', 2, 3)];
print(total(shapes), shapes[0] instanceof Circle, typeof shapes[1], delete (shapes as any)[1]);
