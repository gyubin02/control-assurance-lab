const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

export const DEFAULT_JSON_LIMITS = Object.freeze({
  maxBytes: 16 * 1024 * 1024,
  maxDepth: 64,
  maxCollectionItems: 100_000,
  maxStringLength: 2 * 1024 * 1024,
  maxLineBytes: 2 * 1024 * 1024,
});

export class StrictJsonError extends Error {
  constructor(message) {
    super(message);
    this.name = "StrictJsonError";
  }
}

function utf8(buffer, limits) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError("strict JSON input must be a Buffer");
  }
  if (buffer.length > limits.maxBytes) {
    throw new StrictJsonError("JSON payload exceeds the byte limit");
  }
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xef &&
    buffer[1] === 0xbb &&
    buffer[2] === 0xbf
  ) {
    throw new StrictJsonError("UTF-8 byte-order marks are not allowed");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw new StrictJsonError("JSON payload is not valid UTF-8");
  }
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return true;
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function validateString(value, limits) {
  let length = 0;
  for (const _character of value) {
    length += 1;
    if (length > limits.maxStringLength) {
      throw new StrictJsonError("JSON string exceeds the length limit");
    }
  }
  if (hasUnpairedSurrogate(value)) {
    throw new StrictJsonError("unpaired Unicode surrogate is not allowed");
  }
}

function compareUnicodeCodePoints(left, right) {
  const leftPoints = left[Symbol.iterator]();
  const rightPoints = right[Symbol.iterator]();
  for (;;) {
    const leftPoint = leftPoints.next();
    const rightPoint = rightPoints.next();
    if (leftPoint.done || rightPoint.done) {
      if (leftPoint.done && rightPoint.done) return 0;
      return leftPoint.done ? -1 : 1;
    }
    const leftCodePoint = leftPoint.value.codePointAt(0);
    const rightCodePoint = rightPoint.value.codePointAt(0);
    if (leftCodePoint < rightCodePoint) return -1;
    if (leftCodePoint > rightCodePoint) return 1;
  }
}

function validateNumber(value) {
  if (!Number.isFinite(value)) {
    throw new StrictJsonError("non-finite JSON number is not allowed");
  }
  if (Object.is(value, -0)) {
    throw new StrictJsonError("negative zero is not allowed");
  }
  if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER) {
    throw new StrictJsonError("integral JSON number exceeds the I-JSON range");
  }
}

class Parser {
  constructor(text, limits) {
    this.text = text;
    this.limits = limits;
    this.offset = 0;
  }

  parse() {
    this.skipWhitespace();
    const value = this.value(0);
    this.skipWhitespace();
    if (this.offset !== this.text.length) {
      throw new StrictJsonError("trailing data after the JSON value");
    }
    return value;
  }

  skipWhitespace() {
    while (
      this.offset < this.text.length &&
      (this.text[this.offset] === " " ||
        this.text[this.offset] === "\n" ||
        this.text[this.offset] === "\r" ||
        this.text[this.offset] === "\t")
    ) {
      this.offset += 1;
    }
  }

  value(depth) {
    if (depth > this.limits.maxDepth) {
      throw new StrictJsonError("JSON nesting exceeds the depth limit");
    }
    const character = this.text[this.offset];
    if (character === "{") return this.object(depth + 1);
    if (character === "[") return this.array(depth + 1);
    if (character === '"') return this.string();
    if (character === "t") return this.literal("true", true);
    if (character === "f") return this.literal("false", false);
    if (character === "n") return this.literal("null", null);
    if (character === "-" || (character >= "0" && character <= "9")) {
      return this.number();
    }
    throw new StrictJsonError(`unexpected token at character ${this.offset}`);
  }

  literal(spelling, value) {
    if (this.text.slice(this.offset, this.offset + spelling.length) !== spelling) {
      throw new StrictJsonError(`invalid literal at character ${this.offset}`);
    }
    this.offset += spelling.length;
    return value;
  }

  string() {
    const start = this.offset;
    this.offset += 1;
    let escaped = false;
    while (this.offset < this.text.length) {
      const code = this.text.charCodeAt(this.offset);
      const character = this.text[this.offset];
      if (!escaped && character === '"') {
        this.offset += 1;
        let value;
        try {
          value = JSON.parse(this.text.slice(start, this.offset));
        } catch {
          throw new StrictJsonError(`invalid JSON string at character ${start}`);
        }
        validateString(value, this.limits);
        return value;
      }
      if (!escaped && code < 0x20) {
        throw new StrictJsonError(`unescaped control character at character ${this.offset}`);
      }
      if (!escaped && character === "\\") {
        escaped = true;
      } else {
        escaped = false;
      }
      this.offset += 1;
    }
    throw new StrictJsonError(`unterminated JSON string at character ${start}`);
  }

  number() {
    const remainder = this.text.slice(this.offset);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(remainder);
    if (match === null) {
      throw new StrictJsonError(`invalid JSON number at character ${this.offset}`);
    }
    const raw = match[0];
    this.offset += raw.length;
    const value = Number(raw);
    validateNumber(value);
    const significand = raw.toLowerCase().split("e", 1)[0];
    if (value === 0 && /[1-9]/.test(significand)) {
      throw new StrictJsonError("JSON number underflows binary64");
    }
    return value;
  }

  object(depth) {
    const result = Object.create(null);
    const seen = new Set();
    let count = 0;
    this.offset += 1;
    this.skipWhitespace();
    if (this.text[this.offset] === "}") {
      this.offset += 1;
      return result;
    }
    for (;;) {
      if (this.text[this.offset] !== '"') {
        throw new StrictJsonError(`object key expected at character ${this.offset}`);
      }
      const key = this.string();
      if (seen.has(key)) {
        throw new StrictJsonError(`duplicate object key: ${JSON.stringify(key)}`);
      }
      seen.add(key);
      count += 1;
      if (count > this.limits.maxCollectionItems) {
        throw new StrictJsonError("JSON object exceeds the member limit");
      }
      this.skipWhitespace();
      if (this.text[this.offset] !== ":") {
        throw new StrictJsonError(`colon expected at character ${this.offset}`);
      }
      this.offset += 1;
      this.skipWhitespace();
      result[key] = this.value(depth);
      this.skipWhitespace();
      if (this.text[this.offset] === "}") {
        this.offset += 1;
        return result;
      }
      if (this.text[this.offset] !== ",") {
        throw new StrictJsonError(`comma expected at character ${this.offset}`);
      }
      this.offset += 1;
      this.skipWhitespace();
    }
  }

  array(depth) {
    const result = [];
    this.offset += 1;
    this.skipWhitespace();
    if (this.text[this.offset] === "]") {
      this.offset += 1;
      return result;
    }
    for (;;) {
      if (result.length >= this.limits.maxCollectionItems) {
        throw new StrictJsonError("JSON array exceeds the item limit");
      }
      result.push(this.value(depth));
      this.skipWhitespace();
      if (this.text[this.offset] === "]") {
        this.offset += 1;
        return result;
      }
      if (this.text[this.offset] !== ",") {
        throw new StrictJsonError(`comma expected at character ${this.offset}`);
      }
      this.offset += 1;
      this.skipWhitespace();
    }
  }
}

export function parseStrictJson(buffer, limits = DEFAULT_JSON_LIMITS) {
  return new Parser(utf8(buffer, limits), limits).parse();
}

function canonicalValue(value, limits, depth) {
  if (depth > limits.maxDepth) {
    throw new StrictJsonError("JSON nesting exceeds the depth limit");
  }
  if (value === null || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "number") {
    validateNumber(value);
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    validateString(value, limits);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > limits.maxCollectionItems) {
      throw new StrictJsonError("JSON array exceeds the item limit");
    }
    return `[${value.map((item) => canonicalValue(item, limits, depth + 1)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length > limits.maxCollectionItems) {
      throw new StrictJsonError("JSON object exceeds the member limit");
    }
    keys.sort();
    return `{${keys
      .map((key) => {
        validateString(key, limits);
        return `${JSON.stringify(key)}:${canonicalValue(value[key], limits, depth + 1)}`;
      })
      .join(",")}}`;
  }
  throw new StrictJsonError(`unsupported JSON value type: ${typeof value}`);
}

export function canonicalize(value, limits = DEFAULT_JSON_LIMITS) {
  const encoded = Buffer.from(canonicalValue(value, limits, 0), "utf8");
  if (encoded.length > limits.maxBytes) {
    throw new StrictJsonError("canonical JSON exceeds the byte limit");
  }
  return encoded;
}

export function verifyCanonicalJson(buffer, limits = DEFAULT_JSON_LIMITS) {
  const value = parseStrictJson(buffer, limits);
  if (!canonicalize(value, limits).equals(buffer)) {
    throw new StrictJsonError("JSON is not exact RFC 8785 canonical bytes");
  }
  return value;
}

export function verifyCanonicalJsonLines(buffer, limits = DEFAULT_JSON_LIMITS) {
  if (buffer.length > limits.maxBytes) {
    throw new StrictJsonError("JSONL payload exceeds the byte limit");
  }
  if (buffer.includes(0x0d)) {
    throw new StrictJsonError("canonical JSONL permits LF line endings only");
  }
  if (buffer.length > 0 && buffer.at(-1) !== 0x0a) {
    throw new StrictJsonError("canonical JSONL requires one final LF");
  }
  const lines = [];
  let lineStart = 0;
  while (lineStart < buffer.length) {
    const lineEnd = buffer.indexOf(0x0a, lineStart);
    if (lineEnd === -1) break;
    if (lines.length >= limits.maxCollectionItems) {
      throw new StrictJsonError("JSONL record count exceeds the configured limit");
    }
    lines.push(buffer.subarray(lineStart, lineEnd));
    lineStart = lineEnd + 1;
  }
  let previousId = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.length === 0) {
      throw new StrictJsonError(`blank JSONL line at ${index + 1}`);
    }
    if (line.length > limits.maxLineBytes) {
      throw new StrictJsonError(`JSONL line ${index + 1} exceeds the byte limit`);
    }
    const value = verifyCanonicalJson(line, limits);
    if (value === null || Array.isArray(value) || typeof value !== "object") {
      throw new StrictJsonError(`JSONL line ${index + 1} is not an object`);
    }
    if (typeof value.id !== "string") {
      throw new StrictJsonError(`JSONL line ${index + 1} requires a string id`);
    }
    const order = previousId === null ? 1 : compareUnicodeCodePoints(value.id, previousId);
    if (previousId !== null && order <= 0) {
      throw new StrictJsonError(
        order === 0 ? "duplicate JSONL id" : "JSONL records are not sorted by id",
      );
    }
    previousId = value.id;
  }
}
