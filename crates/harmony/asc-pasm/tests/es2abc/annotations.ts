// Annotations: API 20 and later, compiled with --enable-annotations. The
// prefix is what the build puts ahead of the name of every annotation. No
// array given to an annotation is empty: the official disassembler crashes
// on one.
@interface __$$ETS_ANNOTATION$$__Marked {
  level: number = 1;
  name: string = 'plain';
  on: boolean = true;
  tags: string[] = ['a', 'b'];
  sizes: number[] = [1, 2.5, -3];
  flags: boolean[] = [true, false];
  grid: number[][] = [[1, 2], [3]];
}

@interface __$$ETS_ANNOTATION$$__Bare {}

@__$$ETS_ANNOTATION$$__Marked({ level: 3, name: 'class', on: false, tags: ['x'], sizes: [0.5], flags: [false], grid: [[4]] })
class Tagged {
  @__$$ETS_ANNOTATION$$__Marked
  @__$$ETS_ANNOTATION$$__Bare
  run(): number {
    return 1;
  }
  @__$$ETS_ANNOTATION$$__Marked({ level: -0.5, tags: ['only'] })
  static make(): Tagged {
    return new Tagged();
  }
}

export const tagged = Tagged.make().run();
