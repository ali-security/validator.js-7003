import test from '../testFunctions';

describe('isLength', () => {
  it('should return false for a string with length greater than the max', () => {
    test({
      validator: 'isLength',
      args: [{ max: 3 }],
      invalid: ['test'],
    });
  });

  it('should return true for a string with length equal to the max', () => {
    test({
      validator: 'isLength',
      args: [{ max: 4 }],
      valid: ['test'],
    });
  });

  it('should correctly calculate the length of a string with presentation sequences', () => {
    test({
      validator: 'isLength',
      args: [{ max: 4 }],
      valid: ['test\uFE0F'],
    });

    test({
      validator: 'isLength',
      args: [{ min: 5, max: 5 }],
      valid: ['test\uFE0F\uFE0F'],
    });

    test({
      validator: 'isLength',
      args: [{ min: 5, max: 5 }],
      valid: ['\uFE0Ftest'],
    });

    test({
      validator: 'isLength',
      args: [{ min: 9, max: 9 }],
      valid: ['test\uFE0F\uFE0F\uFE0F\uFE0F\uFE0F\uFE0F'],
    });
  });

  it('should validate strings by length (deprecated api)', () => {
    test({
      validator: 'isLength',
      args: [2],
      valid: ['abc', 'de', 'abcd'],
      invalid: ['', 'a'],
    });
    test({
      validator: 'isLength',
      args: [2, 3],
      valid: ['abc', 'de'],
      invalid: ['', 'a', 'abcd'],
    });
    test({
      validator: 'isLength',
      args: [2, 3],
      valid: ['干𩸽', '𠮷野家'],
      invalid: ['', '𠀋', '千竈通り'],
    });
    test({
      validator: 'isLength',
      args: [0, 0],
      valid: [''],
      invalid: ['a', 'ab'],
    });
  });

  it('should validate strings by length', () => {
    test({
      validator: 'isLength',
      args: [{ min: 2 }],
      valid: ['abc', 'de', 'abcd'],
      invalid: ['', 'a'],
    });
    test({
      validator: 'isLength',
      args: [{ min: 2, max: 3 }],
      valid: ['abc', 'de'],
      invalid: ['', 'a', 'abcd'],
    });
    test({
      validator: 'isLength',
      args: [{ min: 2, max: 3 }],
      valid: ['干𩸽', '𠮷野家'],
      invalid: ['', '𠀋', '千竈通り'],
    });
    test({
      validator: 'isLength',
      args: [{ max: 3 }],
      valid: ['abc', 'de', 'a', ''],
      invalid: ['abcd'],
    });
    test({
      validator: 'isLength',
      args: [{ max: 0 }],
      valid: [''],
      invalid: ['a', 'ab'],
    });
    test({
      validator: 'isLength',
      valid: ['a', '', 'asds'],
    });
    test({
      validator: 'isLength',
      args: [{ max: 8 }],
      valid: ['👩🦰👩👩👦👦🏳️🌈', '⏩︎⏩︎⏪︎⏪︎⏭︎⏭︎⏮︎⏮︎'],
    });
  });
});
