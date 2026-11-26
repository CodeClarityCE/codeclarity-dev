#!/usr/bin/env node
// Fails when a frontend copy of an API enum, allow-list or object's keys misses values
// the API defines, or a shared file's copy differs. Reads source text only: nothing is built.
// Usage: node scripts/type-sync/check.mjs [checkout root, default: this repo]
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const KINDS = new Set(["enum", "list", "keys", "file"]);

/** Parses pairs.txt: one "kind api-file#symbol frontend-file#symbol" per line; a file pair has no symbols. */
export function parsePairs(text) {
  const pairs = [];
  text.split("\n").forEach((raw, index) => {
    const line = raw.replace(/#\s.*$|^#.*$/, "").trim();
    if (line === "") return;
    const fields = line.split(/\s+/);
    const where = `pairs line ${index + 1}`;
    if (fields.length !== 3) {
      throw new Error(`${where}: expected "kind api#symbol frontend#symbol"`);
    }
    const [kind, api, frontend] = fields;
    if (!KINDS.has(kind))
      throw new Error(`${where}: kind must be enum, list, keys or file`);
    const parse = kind === "file" ? (file) => ({ file, symbol: file }) : target;
    pairs.push({
      kind,
      api: parse(api, where),
      frontend: parse(frontend, where),
    });
  });
  return pairs;
}

function target(field, where) {
  const [file, symbol, extra] = field.split("#");
  if (!file || !symbol || extra !== undefined) {
    throw new Error(`${where}: "${field}" is not file#symbol`);
  }
  return { file, symbol };
}

/** Drops comments, keeping string literals intact. */
function stripComments(source) {
  return source.replace(
    /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    (match, literal) => literal ?? "",
  );
}

/** The text between the brace or bracket that opens at `start` and its match. */
function body(source, start) {
  const open = source[start];
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  for (let i = start; i < source.length; i++) {
    if (source[i] === open) depth++;
    else if (source[i] === close && --depth === 0)
      return source.slice(start + 1, i);
  }
  return null;
}

/** An enum's members as name -> value (a string literal's text or a number), or null. */
export function readEnum(source, symbol) {
  const text = stripComments(source);
  const found = new RegExp(`\\benum\\s+${symbol}\\s*\\{`).exec(text);
  if (!found) return null;
  const inner = body(text, found.index + found[0].length - 1);
  if (inner === null) return null;
  const members = new Map();
  let next = 0;
  for (const part of inner.split(",")) {
    const member = part.trim();
    if (member === "") continue;
    const [, name, init] =
      /^["']?(\w+)["']?\s*(?:=\s*([\s\S]+))?$/.exec(member) ?? [];
    if (!name)
      throw new Error(`enum ${symbol}: cannot read member "${member}"`);
    let value;
    if (init === undefined) value = next;
    else if (/^(["']).*\1$/.test(init.trim())) value = init.trim().slice(1, -1);
    else if (!Number.isNaN(Number(init))) value = Number(init);
    else throw new Error(`enum ${symbol}: cannot read value of ${name}`);
    members.set(name, value);
    if (typeof value === "number") next = value + 1;
  }
  return members;
}

/** The string literals of an array assigned to `symbol`, or null. */
export function readList(source, symbol) {
  const text = stripComments(source);
  const found = new RegExp(`\\b${symbol}\\b[^=]*=\\s*\\[`).exec(text);
  if (!found) return null;
  const inner = body(text, found.index + found[0].length - 1);
  if (inner === null) return null;
  return [...inner.matchAll(/(["'])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2]);
}

/** The top-level keys of an object literal assigned to `symbol`, or null. */
export function readKeys(source, symbol) {
  const text = stripComments(source);
  const found = new RegExp(`\\b${symbol}\\b[^=]*=\\s*\\{`).exec(text);
  if (!found) return null;
  const inner = body(text, found.index + found[0].length - 1);
  if (inner === null) return null;
  // Blank out string values so their commas and colons are not mistaken for entries.
  const flat = inner.replace(
    /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)(\s*:)?/g,
    (literal, _, colon) => (colon ? literal : '""'),
  );
  const keys = [];
  for (const part of flat.split(",")) {
    const [, key] = /^\s*["']?([\w$]+)["']?\s*:/.exec(part) ?? [];
    if (key) keys.push(key);
  }
  return keys;
}

const readers = { enum: readEnum, list: readList, keys: readKeys };

const show = (value) =>
  typeof value === "string" ? `"${value}"` : String(value);

function read(root, ref, kind) {
  let source;
  try {
    source = readFileSync(join(root, ref.file), "utf8");
  } catch {
    return { error: `cannot read ${ref.file}` };
  }
  if (kind === "file") return { value: source };
  const value = readers[kind](source, ref.symbol);
  return value === null
    ? { error: `no ${kind} ${ref.symbol} in ${ref.file}` }
    : { value };
}

/** Every problem across the pairs, one plain line each; empty when all are in sync. */
export function checkPairs(root, pairs) {
  const problems = [];
  for (const { kind, api, frontend } of pairs) {
    const label = `${kind} ${api.symbol}`;
    const a = read(root, api, kind);
    const f = read(root, frontend, kind);
    for (const r of [a, f]) if (r.error) problems.push(`${label}: ${r.error}`);
    if (a.error || f.error) continue;

    if (kind === "file") {
      // A shared file must be byte for byte the same in both places.
      if (a.value !== f.value) {
        problems.push(`${label}: ${frontend.file} differs from it`);
      }
    } else if (kind === "enum") {
      // Every API member must exist in the frontend with the same value; extras are fine.
      for (const [name, value] of a.value) {
        const fe = `${frontend.file}#${frontend.symbol}`;
        if (!f.value.has(name)) {
          problems.push(
            `${label}: ${api.file} has ${name} = ${show(value)}, ${fe} lacks it`,
          );
        } else if (f.value.get(name) !== value) {
          problems.push(
            `${label}: ${api.file} has ${name} = ${show(value)}, ${fe} has ${name} = ${show(f.value.get(name))}`,
          );
        }
      }
    } else if (kind === "keys") {
      // Every API key must be a key of the frontend object; extras are fine.
      for (const key of a.value) {
        if (!f.value.includes(key)) {
          problems.push(
            `${label}: ${api.file} has ${key}, ${frontend.file}#${frontend.symbol} lacks it`,
          );
        }
      }
    } else {
      // Allow-lists must hold exactly the same entries.
      for (const [from, other, otherRef] of [
        [api, f.value, frontend],
        [frontend, a.value, api],
      ]) {
        const own = from === api ? a.value : f.value;
        for (const entry of own) {
          if (!other.includes(entry)) {
            problems.push(
              `${label}: ${from.file} has ${show(entry)}, ${otherRef.file}#${otherRef.symbol} lacks it`,
            );
          }
        }
      }
    }
  }
  return problems;
}

// Run as a script: check the pairs next to this file against a checkout.
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = resolve(process.argv[2] ?? join(here, "..", ".."));
  const pairs = parsePairs(readFileSync(join(here, "pairs.txt"), "utf8"));
  const problems = checkPairs(root, pairs);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`::error::${problem}`);
    console.error(
      `${problems.length} problem(s). Bring the copy in line with the API's, then bump the submodule pointers.`,
    );
    process.exit(1);
  }
  console.log(`${pairs.length} pairs in sync.`);
}
