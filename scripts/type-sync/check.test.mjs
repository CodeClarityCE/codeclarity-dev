// Tests for check.mjs: run with `node --test scripts/type-sync/check.test.mjs`.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { checkPairs, parsePairs } from "./check.mjs";

const API_ENUM = `
// The kind of action.
export enum ActionType {
  ProjectCreate = "ProjectCreate", // inline comment
  ProjectDelete = 'ProjectDelete',
  /* block comment */
  AnalyzerCreate = "AnalyzerCreate",
}
export enum ActionSeverity {
  Low = 0,
  High = 3,
}
`;
const FRONTEND_ENUM = `
export enum ActionType {
  ProjectCreate = "ProjectCreate",
  ProjectDelete = "ProjectDelete",
  AnalyzerCreate = "AnalyzerCreate",
}
export enum ActionSeverity {
  Low = 0,
  High = 3,
}
`;
const API_LIST = `const ALLOWED_FIELDS = [\n  "route",\n  "stack",\n] as const;\n`;

const API_KEYS = `
export const errorMessages: Record<string, string> = {
  NotAuthorized: "You are not authorized, sorry: really.",
  "EntityInUse": 'Still used, by: others.',
  // A comment.
  InvitationExpired: "Invitation expired.",
};
`;
const FRONTEND_KEYS = `
export const APIErrors = {
  NotAuthorized: "NotAuthorized",
  EntityInUse: "EntityInUse",
  InvitationExpired: "InvitationExpired",
  InternalError: "InternalError",
} as const;
`;

const PAIRS = `
# kind  api file#symbol  frontend file#symbol
enum  api/types.ts#ActionType  frontend/AuditLog.ts#ActionType
enum  api/types.ts#ActionSeverity  frontend/AuditLog.ts#ActionSeverity
list  api/logs.ts#ALLOWED_FIELDS  frontend/logger.ts#ALLOWED_FIELDS
file  api/cases.json  backend/vuln-finder/cases.json
keys  api/errors.ts#errorMessages  frontend/ApiErrors.ts#APIErrors
`;

const CASES = `[{ "name": "a case", "hidden": null }]\n`;

// Writes a checkout with an api and a frontend copy, overriding any file.
function checkout(files = {}) {
  const root = mkdtempSync(join(tmpdir(), "type-sync-"));
  const all = {
    "api/types.ts": API_ENUM,
    "frontend/AuditLog.ts": FRONTEND_ENUM,
    "api/logs.ts": API_LIST,
    "frontend/logger.ts": API_LIST,
    "api/cases.json": CASES,
    "backend/vuln-finder/cases.json": CASES,
    "api/errors.ts": API_KEYS,
    "frontend/ApiErrors.ts": FRONTEND_KEYS,
    ...files,
  };
  for (const [path, text] of Object.entries(all)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

const check = (files) => checkPairs(checkout(files), parsePairs(PAIRS));

test("copies in sync report nothing", () => {
  assert.deepEqual(check(), []);
});

test("a value added only to the API enum is named", () => {
  const api = API_ENUM.replace(
    'AnalyzerCreate = "AnalyzerCreate",',
    'AnalyzerCreate = "AnalyzerCreate",\n  TicketCreate = "TicketCreate",',
  );
  assert.deepEqual(check({ "api/types.ts": api }), [
    'enum ActionType: api/types.ts has TicketCreate = "TicketCreate", frontend/AuditLog.ts#ActionType lacks it',
  ]);
});

test("an extra value in the frontend enum is allowed", () => {
  const frontend = FRONTEND_ENUM.replace("Low = 0,", "Low = 0,\n  Medium = 1,");
  assert.deepEqual(check({ "frontend/AuditLog.ts": frontend }), []);
});

test("a value that differs is named with both values", () => {
  const frontend = FRONTEND_ENUM.replace("High = 3,", "High = 2,");
  assert.deepEqual(check({ "frontend/AuditLog.ts": frontend }), [
    "enum ActionSeverity: api/types.ts has High = 3, frontend/AuditLog.ts#ActionSeverity has High = 2",
  ]);
});

test("implicit enum values count up from the previous one", () => {
  const api = API_ENUM.replace("Low = 0,\n  High = 3,", "Low,\n  High = 3,");
  assert.deepEqual(check({ "api/types.ts": api }), []);
});

test("changing one entry of either allow-list is a failure", () => {
  const changed = API_LIST.replace('"stack"', '"stacktrace"');
  assert.deepEqual(check({ "frontend/logger.ts": changed }), [
    'list ALLOWED_FIELDS: api/logs.ts has "stack", frontend/logger.ts#ALLOWED_FIELDS lacks it',
    'list ALLOWED_FIELDS: frontend/logger.ts has "stacktrace", api/logs.ts#ALLOWED_FIELDS lacks it',
  ]);
  assert.equal(check({ "api/logs.ts": changed }).length, 2);
});

test("a shared file whose copy differs is named", () => {
  const changed = CASES.replace("null", '"contradicted"');
  assert.deepEqual(check({ "backend/vuln-finder/cases.json": changed }), [
    "file api/cases.json: backend/vuln-finder/cases.json differs from it",
  ]);
});

test("a key added only to the API object is named", () => {
  const api = API_KEYS.replace(
    'InvitationExpired: "Invitation expired.",',
    'InvitationExpired: "Invitation expired.",\n  NotAMember: "Not a member.",',
  );
  assert.deepEqual(check({ "api/errors.ts": api }), [
    "keys errorMessages: api/errors.ts has NotAMember, frontend/ApiErrors.ts#APIErrors lacks it",
  ]);
});

test("an extra key in the frontend object is allowed", () => {
  const api = API_KEYS.replace(
    '  InvitationExpired: "Invitation expired.",\n',
    "",
  );
  assert.deepEqual(check({ "api/errors.ts": api }), []);
});

test("a symbol that cannot be found fails with a clear message", () => {
  const renamed = FRONTEND_ENUM.replace(
    "enum ActionType",
    "enum AuditActionType",
  );
  assert.deepEqual(check({ "frontend/AuditLog.ts": renamed }), [
    "enum ActionType: no enum ActionType in frontend/AuditLog.ts",
  ]);
});

test("a missing file fails with a clear message", () => {
  const root = checkout();
  const pairs = parsePairs(
    "enum api/gone.ts#ActionType frontend/AuditLog.ts#ActionType",
  );
  assert.deepEqual(checkPairs(root, pairs), [
    "enum ActionType: cannot read api/gone.ts",
  ]);
});

test("a malformed pair line is refused", () => {
  assert.throws(() => parsePairs("enum api/types.ts#ActionType"), /line 1/);
  assert.throws(
    () => parsePairs("set api/a.ts#A frontend/b.ts#B"),
    /kind must be enum, list, keys or file/,
  );
});

test("the declared pairs name existing files in this repository", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const pairs = parsePairs(readFileSync(join(here, "pairs.txt"), "utf8"));
  assert.ok(pairs.length >= 10);
  for (const pair of pairs) {
    assert.match(pair.api.file, /^api\//);
    if (pair.kind !== "file") assert.match(pair.frontend.file, /^frontend\//);
  }
  assert.ok(pairs.some((pair) => pair.kind === "file"));
});
