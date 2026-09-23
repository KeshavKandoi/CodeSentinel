export type StringRange = [number, number];

export function scanPython(src: string): { code: string; ranges: StringRange[] } {
  const out: string[] = [];
  const ranges: StringRange[] = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const c = src.charAt(i);
    if (c === '"' || c === "'") {
      const quote3 = c.repeat(3);
      let j: number;
      if (src.startsWith(quote3, i)) {
        const close = src.indexOf(quote3, i + 3);
        j = close === -1 ? n : close + 3;
      } else {
        j = i + 1;
        while (j < n && src.charAt(j) !== c && src.charAt(j) !== '\n') {
          if (src.charAt(j) === '\\') j++;
          j++;
        }
        j = Math.min(n, j + 1);
      }
      ranges.push([i, j]);
      out.push(src.slice(i, j));
      i = j;
    } else if (c === '#') {
      let j = i;
      while (j < n && src.charAt(j) !== '\n') j++;
      out.push(' '.repeat(j - i));
      i = j;
    } else {
      out.push(c);
      i++;
    }
  }
  return { code: out.join(''), ranges };
}

export function insideRange(ranges: readonly StringRange[], index: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = ranges[mid];
    if (!r) return false;
    if (index < r[0]) hi = mid - 1;
    else if (index >= r[1]) lo = mid + 1;
    else return true;
  }
  return false;
}

export function blankRanges(code: string, ranges: readonly StringRange[]): string {
  const parts: string[] = [];
  let last = 0;
  for (const [start, end] of ranges) {
    parts.push(code.slice(last, start));
    parts.push(code.slice(start, end).replace(/[^\n]/g, ' '));
    last = end;
  }
  parts.push(code.slice(last));
  return parts.join('');
}

export function matchClose(text: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'") {
      const quote3 = c.repeat(3);
      if (text.startsWith(quote3, i)) {
        const end = text.indexOf(quote3, i + 3);
        if (end === -1) return -1;
        i = end + 2;
      } else {
        i++;
        while (i < text.length && text.charAt(i) !== c && text.charAt(i) !== '\n') {
          if (text.charAt(i) === '\\') i++;
          i++;
        }
      }
    } else if (c === '(' || c === '[' || c === '{') {
      depth++;
    } else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export function splitTopLevel(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'") {
      const quote3 = c.repeat(3);
      if (text.startsWith(quote3, i)) {
        const end = text.indexOf(quote3, i + 3);
        if (end === -1) break;
        i = end + 2;
      } else {
        i++;
        while (i < text.length && text.charAt(i) !== c && text.charAt(i) !== '\n') {
          if (text.charAt(i) === '\\') i++;
          i++;
        }
      }
    } else if (c === '(' || c === '[' || c === '{') {
      depth++;
    } else if (c === ')' || c === ']' || c === '}') {
      depth--;
    } else if (c === ',' && depth === 0) {
      out.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  const tail = text.slice(start).trim();
  if (tail !== '') out.push(tail);
  return out;
}

export function lineOf(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}
