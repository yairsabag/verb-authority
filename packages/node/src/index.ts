import { createHmac, randomBytes } from "node:crypto";
import { types as utilTypes } from "node:util";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type Authority =
  | "trusted_fixed"
  | "typed_bounded"
  | "outbound_payload";

export type Risk =
  | "unknown"
  | "read_only"
  | "write"
  | "financial"
  | "destructive"
  | "code_exec";

export type ParamType =
  | "string"
  | "number"
  | "integer"
  | "boolean"
  | "object"
  | "array"
  | "json";

export interface ParamRegistration {
  readonly name: string;
  readonly authority: Authority;
  readonly type: ParamType;
  readonly enum?: readonly JsonValue[];
  readonly maxLength?: number;
  readonly maxItems?: number;
  readonly maxProperties?: number;
  readonly minimum?: number;
  readonly maximum?: number;
}

export type ToolHandler = (
  this: void,
  input: Readonly<Record<string, JsonValue>>,
) => JsonValue | Promise<JsonValue>;

export interface ToolRegistration {
  readonly name: string;
  readonly risk: Risk;
  readonly params: readonly ParamRegistration[];
  readonly handler: ToolHandler;
  readonly requiresConfirmation?: boolean;
}

export interface ToolCall {
  readonly name: string;
  readonly input: Readonly<Record<string, JsonValue>>;
}

export type DecisionCode =
  | "allowed"
  | "invalid_call"
  | "unknown_tool"
  | "unknown_argument"
  | "missing_argument"
  | "invalid_trusted_args"
  | "trusted_value_mismatch"
  | "constraint_violation"
  | "confirmation_required"
  | "confirmation_denied"
  | "confirmation_error"
  | "internal_revalidation_failed";

export interface Decision {
  readonly allow: boolean;
  readonly code: DecisionCode;
  readonly reason: string;
  readonly needsConfirmation: boolean;
}

export interface ConfirmationRequest {
  readonly toolName: string;
  readonly argumentsJson: string;
  readonly risk: Risk;
  readonly registrationId: string;
  /** Unique for this one in-flight confirmation attempt. */
  readonly confirmationId: string;
  /** Deterministic exact policy-and-argument commitment within this runner. */
  readonly actionDigest: string;
}

export type ConfirmationCallback = (
  this: void,
  request: ConfirmationRequest,
) => boolean | Promise<boolean>;

export interface RunOptions {
  readonly trustedArgs?: Readonly<Record<string, JsonValue>>;
  readonly confirm?: ConfirmationCallback;
}

export type ContractViolation =
  | "confirmation_exception"
  | "invocation_exception"
  | "unsupported_result";

export interface ExecutionResult {
  /** Pre-execution authority decision; it remains allowed after dispatch errors. */
  readonly decision: Decision;
  /** True once the private registered handler has been entered. */
  readonly invoked: boolean;
  /** True when the handler returned or its accepted native Promise resolved. */
  readonly handlerCompleted: boolean;
  /** True only when a detached finite plain-JSON result is available. */
  readonly resultValidated: boolean;
  readonly result?: JsonValue;
  readonly contractViolation?: ContractViolation;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_-]{0,127}$/u;
const AUTHORITIES = new Set<Authority>([
  "trusted_fixed",
  "typed_bounded",
  "outbound_payload",
]);
const RISKS = new Set<Risk>([
  "unknown",
  "read_only",
  "write",
  "financial",
  "destructive",
  "code_exec",
]);
const PARAM_TYPES = new Set<ParamType>([
  "string",
  "number",
  "integer",
  "boolean",
  "object",
  "array",
  "json",
]);
const CONFIRMATION_RISKS = new Set<Risk>([
  "unknown",
  "financial",
  "destructive",
  "code_exec",
]);

// Registered handlers are trusted application code. Capture the intrinsic
// Promise machinery once so a returned Promise cannot redirect settlement
// through an own or prototype-level `then` override. Promise constructor and
// species behavior remains part of that trusted handler boundary.
const NATIVE_PROMISE = Promise;
const NATIVE_PROMISE_THEN = Promise.prototype.then;
const OBJECT_HAS_OWN = Object.hasOwn;
const PREPARED_RUN_TAG: unique symbol = Symbol("prepared-run");

const MAX_TOOLS = 256;
const MAX_PARAMS_PER_TOOL = 256;
const MAX_DEPTH = 64;
const MAX_MATERIAL = 8 * 1024 * 1024;
const MAX_VALUES_AND_KEYS = 100_000;
const PROTOTYPE_SENSITIVE_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

interface SnapshotBudget {
  material: number;
  valuesAndKeys: number;
}

interface FrozenParam {
  readonly name: string;
  readonly authority: Authority;
  readonly type: ParamType;
  readonly enumValues: readonly JsonValue[] | null;
  readonly maxLength: number | null;
  readonly maxItems: number | null;
  readonly maxProperties: number | null;
  readonly minimum: number | null;
  readonly maximum: number | null;
}

interface FrozenTool {
  readonly name: string;
  readonly risk: Risk;
  readonly params: readonly FrozenParam[];
  readonly paramsByName: ReadonlyMap<string, FrozenParam>;
  readonly handler: ToolHandler;
  readonly requiresConfirmation: boolean;
  readonly handlerToken: string;
  readonly registrationId: string;
}

interface PreparedRun {
  readonly [PREPARED_RUN_TAG]: true;
  readonly tool: FrozenTool;
  readonly input: Readonly<Record<string, JsonValue>>;
  readonly trustedArgs: Readonly<Record<string, JsonValue>>;
  readonly needsConfirmation: boolean;
}

interface PlainDataRecord {
  readonly values: ReadonlyMap<string, unknown>;
  readonly keys: readonly string[];
}

class SnapshotError extends Error {}

function hasOwn(value: object, key: PropertyKey): boolean {
  return OBJECT_HAS_OWN(value, key);
}

function isPreparedRun(value: PreparedRun | Decision): value is PreparedRun {
  return hasOwn(value, PREPARED_RUN_TAG);
}

function makeDecision(
  allow: boolean,
  code: DecisionCode,
  reason: string,
  needsConfirmation = false,
): Decision {
  const value = Object.create(null) as {
    allow: boolean;
    code: DecisionCode;
    reason: string;
    needsConfirmation: boolean;
  };
  value.allow = allow;
  value.code = code;
  value.reason = reason;
  value.needsConfirmation = needsConfirmation;
  return Object.freeze(value);
}

function makeResult(
  decision: Decision,
  invoked: boolean,
  handlerCompleted: boolean,
  resultValidated: boolean,
  result?: JsonValue,
  contractViolation?: ContractViolation,
): ExecutionResult {
  const value: {
    decision: Decision;
    invoked: boolean;
    handlerCompleted: boolean;
    resultValidated: boolean;
    result?: JsonValue;
    contractViolation?: ContractViolation;
  } = Object.create(null) as {
    decision: Decision;
    invoked: boolean;
    handlerCompleted: boolean;
    resultValidated: boolean;
    result?: JsonValue;
    contractViolation?: ContractViolation;
  };
  value.decision = decision;
  value.invoked = invoked;
  value.handlerCompleted = handlerCompleted;
  value.resultValidated = resultValidated;
  if (result !== undefined) value.result = result;
  if (contractViolation !== undefined) {
    value.contractViolation = contractViolation;
  }
  return Object.freeze(value);
}

function isKnownExoticObject(value: object): boolean {
  return (
    utilTypes.isAnyArrayBuffer(value) ||
    utilTypes.isArgumentsObject(value) ||
    utilTypes.isArrayBufferView(value) ||
    utilTypes.isBoxedPrimitive(value) ||
    utilTypes.isCryptoKey(value) ||
    utilTypes.isDate(value) ||
    utilTypes.isExternal(value) ||
    utilTypes.isGeneratorObject(value) ||
    utilTypes.isKeyObject(value) ||
    utilTypes.isMap(value) ||
    utilTypes.isMapIterator(value) ||
    utilTypes.isModuleNamespaceObject(value) ||
    utilTypes.isNativeError(value) ||
    utilTypes.isPromise(value) ||
    utilTypes.isRegExp(value) ||
    utilTypes.isSet(value) ||
    utilTypes.isSetIterator(value) ||
    utilTypes.isWeakMap(value) ||
    utilTypes.isWeakSet(value)
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    isKnownExoticObject(value)
  ) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function readPlainDataRecord(
  value: unknown,
  label: string,
  maxFields = MAX_VALUES_AND_KEYS,
): PlainDataRecord {
  if (!isPlainObject(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length > maxFields) {
    throw new TypeError(`${label} contains too many fields`);
  }
  const keys: string[] = [];
  const values = new Map<string, unknown>();
  for (const key of ownKeys) {
    if (typeof key !== "string") {
      throw new TypeError(`${label} must not contain symbol keys`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !hasOwn(descriptor, "value")
    ) {
      throw new TypeError(`${label} must contain only enumerable data fields`);
    }
    keys.push(key);
    values.set(key, descriptor.value);
  }
  return Object.freeze({ keys: Object.freeze(keys), values });
}

function readDenseArray(
  value: unknown,
  label: string,
  maxItems = MAX_VALUES_AND_KEYS,
): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    throw new TypeError(`${label} must be a plain dense array`);
  }
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new TypeError(`${label} has an invalid length`);
  }
  if (length > maxItems) {
    throw new TypeError(`${label} contains too many items`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new TypeError(`${label} must not contain symbol keys`);
  }
  const expectedKeys = new Set<string>(["length"]);
  const output: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    expectedKeys.add(key);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !hasOwn(descriptor, "value")
    ) {
      throw new TypeError(`${label} must not be sparse or contain accessors`);
    }
    output.push(descriptor.value);
  }
  if (
    ownKeys.length !== expectedKeys.size ||
    ownKeys.some((key) => !expectedKeys.has(String(key)))
  ) {
    throw new TypeError(`${label} must not contain extra properties`);
  }
  return Object.freeze(output);
}

function assertAllowedKeys(
  record: PlainDataRecord,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  for (const key of record.keys) {
    if (!allowed.has(key)) {
      throw new TypeError(`${label} contains unknown field '${key}'`);
    }
  }
}

function requireOwn(
  record: PlainDataRecord,
  key: string,
  label: string,
): unknown {
  if (!record.values.has(key)) {
    throw new TypeError(`${label} must include '${key}'`);
  }
  return record.values.get(key);
}

function requireIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} must be a bounded ASCII identifier`);
  }
  return value;
}

function requireArgumentIdentifier(value: unknown, label: string): string {
  const identifier = requireIdentifier(value, label);
  if (PROTOTYPE_SENSITIVE_KEYS.has(identifier)) {
    throw new TypeError(`${label} is prototype-sensitive and unsupported`);
  }
  return identifier;
}

function optionalBoolean(
  record: PlainDataRecord,
  key: string,
  defaultValue: boolean,
  label: string,
): boolean {
  if (!record.values.has(key)) return defaultValue;
  const value = record.values.get(key);
  if (typeof value !== "boolean") {
    throw new TypeError(`${label}.${key} must be boolean`);
  }
  return value;
}

function optionalBound(
  record: PlainDataRecord,
  key: string,
  label: string,
  integer: boolean,
): number | null {
  if (!record.values.has(key)) return null;
  const value = record.values.get(key);
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    (integer && (!Number.isSafeInteger(value) || value < 0))
  ) {
    throw new TypeError(`${label}.${key} is not a valid bound`);
  }
  return value;
}

function assertNoLoneSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new SnapshotError("strings must not contain lone surrogates");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new SnapshotError("strings must not contain lone surrogates");
    }
  }
}

function charge(
  budget: SnapshotBudget,
  material: number,
  valuesAndKeys = 1,
): void {
  budget.material += material;
  budget.valuesAndKeys += valuesAndKeys;
  if (
    budget.material > MAX_MATERIAL ||
    budget.valuesAndKeys > MAX_VALUES_AND_KEYS
  ) {
    throw new SnapshotError("plain JSON snapshot budget exceeded");
  }
}

function stringMaterial(value: string): number {
  return 2 + value.length * 6;
}

function snapshotJson(
  value: unknown,
  budget: SnapshotBudget,
  seen: WeakSet<object>,
  depth = 0,
): JsonValue {
  if (depth > MAX_DEPTH) {
    throw new SnapshotError("plain JSON nesting depth exceeded");
  }
  if (value === null) {
    charge(budget, 4);
    return null;
  }
  if (typeof value === "boolean") {
    charge(budget, value ? 4 : 5);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new SnapshotError("numbers must be finite");
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new SnapshotError("integers must be safe JavaScript integers");
    }
    charge(budget, 32);
    return value;
  }
  if (typeof value === "string") {
    charge(budget, stringMaterial(value));
    assertNoLoneSurrogates(value);
    return value;
  }
  if (typeof value !== "object") {
    throw new SnapshotError("values must be finite plain JSON");
  }
  if (seen.has(value)) {
    throw new SnapshotError("cycles and shared container aliases are unsupported");
  }
  seen.add(value);
  charge(budget, 2);

  if (Array.isArray(value)) {
    const values = readDenseArray(
      value,
      "JSON array",
      Math.max(0, MAX_VALUES_AND_KEYS - budget.valuesAndKeys),
    );
    const output: JsonValue[] = [];
    for (const item of values) {
      output.push(snapshotJson(item, budget, seen, depth + 1));
      charge(budget, 1, 0);
    }
    return Object.freeze(output);
  }

  const record = readPlainDataRecord(
    value,
    "JSON object",
    Math.max(
      0,
      Math.floor((MAX_VALUES_AND_KEYS - budget.valuesAndKeys) / 2),
    ),
  );
  const output: Record<string, JsonValue> = Object.create(null) as Record<
    string,
    JsonValue
  >;
  for (const key of record.keys) {
    // Account conservatively for both the colon and one field separator.
    charge(budget, stringMaterial(key) + 2);
    assertNoLoneSurrogates(key);
    if (PROTOTYPE_SENSITIVE_KEYS.has(key)) {
      throw new SnapshotError("prototype-sensitive JSON keys are unsupported");
    }
    const child = snapshotJson(record.values.get(key), budget, seen, depth + 1);
    Object.defineProperty(output, key, {
      value: child,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(output);
}

function quoteAscii(value: string): string {
  // Deliberately match UTF-16 code units rather than Unicode code points so
  // astral characters become two explicit surrogate escapes as well.
  return JSON.stringify(value).replace(/[<>&\u007f-\uffff]/g, (character) => {
    return `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`;
  });
}

function asJsonObject(value: JsonValue): { readonly [key: string]: JsonValue } {
  return value as { readonly [key: string]: JsonValue };
}

function serializeAscii(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    return Object.is(value, -0) ? "-0" : String(value);
  }
  if (typeof value === "string") return quoteAscii(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeAscii(item)).join(",")}]`;
  }
  const objectValue = asJsonObject(value);
  const fields = Object.keys(objectValue).map((key) => {
    return `${quoteAscii(key)}:${serializeAscii(objectValue[key] as JsonValue)}`;
  });
  return `{${fields.join(",")}}`;
}

function sameJson(left: JsonValue, right: JsonValue): boolean {
  if (typeof left !== typeof right) return false;
  if (left === null || right === null) return left === right;
  if (typeof left === "number" && typeof right === "number") {
    return Object.is(left, right);
  }
  if (
    typeof left === "string" ||
    typeof left === "boolean" ||
    typeof right === "string" ||
    typeof right === "boolean"
  ) {
    return left === right;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) return false;
    if (left.length !== right.length) return false;
    return left.every((item, index) => sameJson(item, right[index] as JsonValue));
  }
  const leftObject = asJsonObject(left);
  const rightObject = asJsonObject(right);
  const leftKeys = Object.keys(leftObject);
  const rightKeys = Object.keys(rightObject);
  if (
    leftKeys.length !== rightKeys.length ||
    leftKeys.some((key, index) => key !== rightKeys[index])
  ) {
    return false;
  }
  return leftKeys.every((key) => {
    return sameJson(
      leftObject[key] as JsonValue,
      rightObject[key] as JsonValue,
    );
  });
}

function isGenuineNativePromise(value: unknown): value is Promise<JsonValue> {
  return (
    value !== null &&
    typeof value === "object" &&
    !utilTypes.isProxy(value) &&
    utilTypes.isPromise(value)
  );
}

interface NativePromiseObservation {
  readonly completion: Promise<boolean>;
  readonly readValue: () => unknown;
}

function observeNativePromise(
  value: Promise<unknown>,
): NativePromiseObservation {
  let fulfilledValue: unknown;
  const completion = new NATIVE_PROMISE<boolean>((resolve) => {
    const constructorDescriptor = Object.getOwnPropertyDescriptor(
      value,
      "constructor",
    );
    let shadowedConstructor = false;
    try {
      if (constructorDescriptor === undefined) {
        if (Object.isExtensible(value)) {
          Object.defineProperty(value, "constructor", {
            value: undefined,
            writable: true,
            enumerable: false,
            configurable: true,
          });
          shadowedConstructor = true;
        }
      } else if (
        constructorDescriptor.configurable ||
        (hasOwn(constructorDescriptor, "value") &&
          constructorDescriptor.writable === true)
      ) {
        Object.defineProperty(value, "constructor", {
          value: undefined,
          writable: true,
          enumerable: constructorDescriptor.enumerable ?? false,
          configurable: constructorDescriptor.configurable ?? false,
        });
        shadowedConstructor = true;
      }
    } catch {
      // A genuine but unusual Promise shell belongs to trusted handler code.
      // Fall through to the captured intrinsic so its rejection is still
      // observed whenever the public Promise API permits that.
      shadowedConstructor = false;
    }

    try {
      Reflect.apply(NATIVE_PROMISE_THEN, value, [
        (result: unknown) => {
          fulfilledValue = result;
          resolve(true);
        },
        () => {
          resolve(false);
        },
      ]);
    } finally {
      if (shadowedConstructor) {
        if (constructorDescriptor === undefined) {
          if (!Reflect.deleteProperty(value, "constructor")) {
            throw new TypeError("could not restore Promise constructor state");
          }
        } else {
          Object.defineProperty(value, "constructor", constructorDescriptor);
        }
      }
    }
  });
  return Object.freeze({
    completion,
    readValue: () => fulfilledValue,
  });
}

function codePointLength(value: string): number {
  return Array.from(value).length;
}

function valueMatchesParam(value: JsonValue, param: FrozenParam): boolean {
  let typeMatches = false;
  switch (param.type) {
    case "string":
      typeMatches = typeof value === "string";
      break;
    case "number":
      typeMatches = typeof value === "number" && Number.isFinite(value);
      break;
    case "integer":
      typeMatches = typeof value === "number" && Number.isSafeInteger(value);
      break;
    case "boolean":
      typeMatches = typeof value === "boolean";
      break;
    case "object":
      typeMatches = value !== null && typeof value === "object" && !Array.isArray(value);
      break;
    case "array":
      typeMatches = Array.isArray(value);
      break;
    case "json":
      typeMatches = true;
      break;
  }
  if (!typeMatches) return false;
  if (
    param.enumValues !== null &&
    !param.enumValues.some((candidate) => sameJson(value, candidate))
  ) {
    return false;
  }
  if (
    typeof value === "string" &&
    param.maxLength !== null &&
    codePointLength(value) > param.maxLength
  ) {
    return false;
  }
  if (
    Array.isArray(value) &&
    param.maxItems !== null &&
    value.length > param.maxItems
  ) {
    return false;
  }
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    param.maxProperties !== null &&
    Object.keys(value).length > param.maxProperties
  ) {
    return false;
  }
  if (
    typeof value === "number" &&
    ((param.minimum !== null && value < param.minimum) ||
      (param.maximum !== null && value > param.maximum))
  ) {
    return false;
  }
  return true;
}

const PARAM_KEYS = new Set([
  "name",
  "authority",
  "type",
  "enum",
  "maxLength",
  "maxItems",
  "maxProperties",
  "minimum",
  "maximum",
]);
const TOOL_KEYS = new Set([
  "name",
  "risk",
  "params",
  "handler",
  "requiresConfirmation",
]);
const OPTION_KEYS = new Set(["trustedArgs", "confirm"]);

function freezeParam(value: unknown, label: string): FrozenParam {
  const record = readPlainDataRecord(value, label, PARAM_KEYS.size);
  assertAllowedKeys(record, PARAM_KEYS, label);
  const name = requireArgumentIdentifier(
    requireOwn(record, "name", label),
    `${label}.name`,
  );
  const authority = requireOwn(record, "authority", label);
  if (typeof authority !== "string" || !AUTHORITIES.has(authority as Authority)) {
    throw new TypeError(`${label}.authority is invalid`);
  }
  const type = requireOwn(record, "type", label);
  if (typeof type !== "string" || !PARAM_TYPES.has(type as ParamType)) {
    throw new TypeError(`${label}.type is invalid`);
  }
  const maxLength = optionalBound(record, "maxLength", label, true);
  const maxItems = optionalBound(record, "maxItems", label, true);
  const maxProperties = optionalBound(record, "maxProperties", label, true);
  const minimum = optionalBound(record, "minimum", label, false);
  const maximum = optionalBound(record, "maximum", label, false);
  if (maxLength !== null && type !== "string") {
    throw new TypeError(`${label}.maxLength requires type 'string'`);
  }
  if (maxItems !== null && type !== "array") {
    throw new TypeError(`${label}.maxItems requires type 'array'`);
  }
  if (maxProperties !== null && type !== "object") {
    throw new TypeError(`${label}.maxProperties requires type 'object'`);
  }
  if ((minimum !== null || maximum !== null) && type !== "number" && type !== "integer") {
    throw new TypeError(`${label} numeric bounds require number or integer type`);
  }
  if (minimum !== null && maximum !== null && minimum > maximum) {
    throw new TypeError(`${label}.minimum must not exceed maximum`);
  }
  if (
    type === "integer" &&
    [minimum, maximum].some(
      (bound) => bound !== null && !Number.isSafeInteger(bound),
    )
  ) {
    throw new TypeError(`${label} integer bounds must be safe integers`);
  }

  let enumValues: readonly JsonValue[] | null = null;
  if (record.values.has("enum")) {
    const rawValues = readDenseArray(
      record.values.get("enum"),
      `${label}.enum`,
      1_000,
    );
    if (rawValues.length === 0 || rawValues.length > 1_000) {
      throw new TypeError(`${label}.enum must contain 1 to 1000 values`);
    }
    const budget: SnapshotBudget = { material: 0, valuesAndKeys: 0 };
    const values = rawValues.map((candidate) => {
      return snapshotJson(candidate, budget, new WeakSet<object>());
    });
    enumValues = Object.freeze(values);
  }

  const frozen = Object.freeze({
    name,
    authority: authority as Authority,
    type: type as ParamType,
    enumValues,
    maxLength,
    maxItems,
    maxProperties,
    minimum,
    maximum,
  });
  if (
    enumValues !== null &&
    enumValues.some((candidate) => !valueMatchesParam(candidate, frozen))
  ) {
    throw new TypeError(`${label}.enum contains a value outside its type or bounds`);
  }
  if (
    enumValues !== null &&
    enumValues.some((candidate, index) => {
      return enumValues?.slice(0, index).some((prior) => sameJson(candidate, prior));
    })
  ) {
    throw new TypeError(`${label}.enum contains duplicate exact values`);
  }
  if (
    authority === "typed_bounded" &&
    enumValues === null &&
    !(
      type === "boolean" ||
      (type === "string" && maxLength !== null) ||
      (type === "array" && maxItems !== null) ||
      (type === "object" && maxProperties !== null) ||
      ((type === "number" || type === "integer") &&
        (minimum !== null || maximum !== null))
    )
  ) {
    throw new TypeError(
      `${label}.typed_bounded requires an enum or an applicable constraint`,
    );
  }
  return frozen;
}

function registrationMaterial(tool: Omit<FrozenTool, "registrationId">): JsonValue {
  return {
    name: tool.name,
    risk: tool.risk,
    requiresConfirmation: tool.requiresConfirmation,
    handlerToken: tool.handlerToken,
    params: tool.params.map((param) => ({
      name: param.name,
      authority: param.authority,
      type: param.type,
      enum: param.enumValues,
      maxLength: param.maxLength,
      maxItems: param.maxItems,
      maxProperties: param.maxProperties,
      minimum: param.minimum,
      maximum: param.maximum,
    })),
  };
}

function parseRunOptions(options: RunOptions | undefined): {
  trustedArgs: unknown;
  confirm: ConfirmationCallback | undefined;
} {
  if (options === undefined) {
    return { trustedArgs: {}, confirm: undefined };
  }
  const record = readPlainDataRecord(options, "run options", OPTION_KEYS.size);
  assertAllowedKeys(record, OPTION_KEYS, "run options");
  const trustedArgs = record.values.has("trustedArgs")
    ? record.values.get("trustedArgs")
    : {};
  const confirm = record.values.get("confirm");
  if (confirm !== undefined && typeof confirm !== "function") {
    throw new TypeError("run options.confirm must be a function");
  }
  return { trustedArgs, confirm: confirm as ConfirmationCallback | undefined };
}

export class GuardedToolRunner {
  readonly #tools = new Map<string, FrozenTool>();
  readonly #secret = randomBytes(32);

  constructor(registrations: readonly ToolRegistration[]) {
    const rawRegistrations = readDenseArray(
      registrations,
      "registrations",
      MAX_TOOLS,
    );
    if (rawRegistrations.length === 0 || rawRegistrations.length > MAX_TOOLS) {
      throw new TypeError(`registrations must contain 1 to ${MAX_TOOLS} tools`);
    }
    for (let toolIndex = 0; toolIndex < rawRegistrations.length; toolIndex += 1) {
      const label = `registrations[${toolIndex}]`;
      const record = readPlainDataRecord(
        rawRegistrations[toolIndex],
        label,
        TOOL_KEYS.size,
      );
      assertAllowedKeys(record, TOOL_KEYS, label);
      const name = requireIdentifier(requireOwn(record, "name", label), `${label}.name`);
      if (this.#tools.has(name)) {
        throw new TypeError(`duplicate tool registration '${name}'`);
      }
      const risk = requireOwn(record, "risk", label);
      if (typeof risk !== "string" || !RISKS.has(risk as Risk)) {
        throw new TypeError(`${label}.risk is invalid`);
      }
      const rawParams = readDenseArray(
        requireOwn(record, "params", label),
        `${label}.params`,
        MAX_PARAMS_PER_TOOL,
      );
      if (rawParams.length > MAX_PARAMS_PER_TOOL) {
        throw new TypeError(`${label}.params exceeds ${MAX_PARAMS_PER_TOOL}`);
      }
      const params = rawParams.map((param, paramIndex) => {
        return freezeParam(param, `${label}.params[${paramIndex}]`);
      });
      const paramsByName = new Map<string, FrozenParam>();
      for (const param of params) {
        if (paramsByName.has(param.name)) {
          throw new TypeError(`${label} contains duplicate param '${param.name}'`);
        }
        paramsByName.set(param.name, param);
      }
      const handler = requireOwn(record, "handler", label);
      if (typeof handler !== "function") {
        throw new TypeError(`${label}.handler must be a function`);
      }
      const partial = Object.freeze({
        name,
        risk: risk as Risk,
        params: Object.freeze(params),
        paramsByName,
        handler: handler as ToolHandler,
        requiresConfirmation: optionalBoolean(
          record,
          "requiresConfirmation",
          false,
          label,
        ),
        handlerToken: randomBytes(32).toString("hex"),
      });
      const material = serializeAscii(registrationMaterial(partial));
      const registrationId = createHmac("sha256", this.#secret)
        .update("registration\0", "utf8")
        .update(material, "utf8")
        .digest("hex");
      this.#tools.set(name, Object.freeze({ ...partial, registrationId }));
    }
  }

  #prepare(call: unknown, options: RunOptions | undefined): PreparedRun | Decision {
    let parsedOptions: ReturnType<typeof parseRunOptions>;
    try {
      parsedOptions = parseRunOptions(options);
    } catch {
      return makeDecision(
        false,
        "invalid_trusted_args",
        "run options must contain only plain trustedArgs and confirm fields",
      );
    }
    const budget: SnapshotBudget = { material: 0, valuesAndKeys: 0 };
    let approvedCall: JsonValue;
    try {
      approvedCall = snapshotJson(call, budget, new WeakSet<object>());
    } catch {
      return makeDecision(
        false,
        "invalid_call",
        "tool call must contain only bounded finite plain JSON",
      );
    }
    let trustedArgsValue: JsonValue;
    try {
      trustedArgsValue = snapshotJson(
        parsedOptions.trustedArgs,
        budget,
        new WeakSet<object>(),
      );
    } catch {
      return makeDecision(
        false,
        "invalid_trusted_args",
        "trustedArgs must contain only bounded finite plain JSON",
      );
    }
    if (
      approvedCall === null ||
      typeof approvedCall !== "object" ||
      Array.isArray(approvedCall)
    ) {
      return makeDecision(false, "invalid_call", "tool call must be a plain object");
    }
    const approvedCallObject = asJsonObject(approvedCall);
    const callKeys = Object.keys(approvedCallObject);
    if (
      callKeys.length !== 2 ||
      !callKeys.includes("name") ||
      !callKeys.includes("input")
    ) {
      return makeDecision(
        false,
        "invalid_call",
        "tool call must contain exactly name and input",
      );
    }
    const name = approvedCallObject.name;
    const input = approvedCallObject.input;
    if (
      typeof name !== "string" ||
      !IDENTIFIER.test(name) ||
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      return makeDecision(
        false,
        "invalid_call",
        "tool call name and input have invalid shapes",
      );
    }
    if (
      trustedArgsValue === null ||
      typeof trustedArgsValue !== "object" ||
      Array.isArray(trustedArgsValue)
    ) {
      return makeDecision(
        false,
        "invalid_trusted_args",
        "trustedArgs must be a plain JSON object",
      );
    }
    const tool = this.#tools.get(name);
    if (tool === undefined) {
      return makeDecision(false, "unknown_tool", "tool is not registered");
    }
    const inputObject = asJsonObject(input);
    const trustedArgsObject = asJsonObject(trustedArgsValue);
    const inputKeys = Object.keys(inputObject);
    for (const key of inputKeys) {
      if (!tool.paramsByName.has(key)) {
        return makeDecision(false, "unknown_argument", "tool call contains an unknown argument");
      }
    }
    for (const param of tool.params) {
      if (!hasOwn(inputObject, param.name)) {
        return makeDecision(false, "missing_argument", "tool call is missing a registered argument");
      }
    }
    for (const key of Object.keys(trustedArgsObject)) {
      const param = tool.paramsByName.get(key);
      if (param === undefined || param.authority !== "trusted_fixed") {
        return makeDecision(
          false,
          "invalid_trusted_args",
          "trustedArgs may name only registered trusted_fixed arguments",
        );
      }
    }
    for (const param of tool.params) {
      const value = inputObject[param.name] as JsonValue;
      if (!valueMatchesParam(value, param)) {
        return makeDecision(
          false,
          "constraint_violation",
          "argument failed its registered type, enum, or bounds",
        );
      }
      if (param.authority === "trusted_fixed") {
        if (
          !hasOwn(trustedArgsObject, param.name) ||
          !sameJson(
            value,
            trustedArgsObject[param.name] as JsonValue,
          )
        ) {
          return makeDecision(
            false,
            "trusted_value_mismatch",
            "a trusted_fixed argument did not match trusted application state",
          );
        }
      }
    }
    return Object.freeze({
      [PREPARED_RUN_TAG]: true as const,
      tool,
      input: inputObject,
      trustedArgs: trustedArgsObject,
      needsConfirmation:
        tool.requiresConfirmation || CONFIRMATION_RISKS.has(tool.risk),
    });
  }

  #actionDigest(tool: FrozenTool, argumentsJson: string): string {
    return createHmac("sha256", this.#secret)
      .update("action\0", "utf8")
      .update(tool.registrationId, "ascii")
      .update("\0", "utf8")
      .update(tool.risk, "ascii")
      .update("\0", "utf8")
      .update(argumentsJson, "utf8")
      .digest("hex");
  }

  async run(call: unknown, options?: RunOptions): Promise<ExecutionResult> {
    const prepared = this.#prepare(call, options);
    if (!isPreparedRun(prepared)) {
      return makeResult(prepared, false, false, false);
    }

    let confirmed = !prepared.needsConfirmation;
    let request: ConfirmationRequest | undefined;
    if (prepared.needsConfirmation) {
      let parsedOptions: ReturnType<typeof parseRunOptions>;
      try {
        parsedOptions = parseRunOptions(options);
      } catch {
        return makeResult(
          makeDecision(false, "invalid_trusted_args", "run options are invalid"),
          false,
          false,
          false,
        );
      }
      if (parsedOptions.confirm === undefined) {
        return makeResult(
          makeDecision(
            false,
            "confirmation_required",
            "trusted confirmation is required before execution",
            true,
          ),
          false,
          false,
          false,
        );
      }
      const argumentsJson = serializeAscii(prepared.input);
      const actionDigest = this.#actionDigest(prepared.tool, argumentsJson);
      request = Object.freeze({
        toolName: prepared.tool.name,
        argumentsJson,
        risk: prepared.tool.risk,
        registrationId: prepared.tool.registrationId,
        confirmationId: randomBytes(32).toString("hex"),
        actionDigest,
      });
      try {
        let confirmationResult: unknown = Reflect.apply(
          parsedOptions.confirm,
          undefined,
          [request],
        );
        if (isGenuineNativePromise(confirmationResult)) {
          const observation = observeNativePromise(confirmationResult);
          if (!(await observation.completion)) {
            throw new TypeError("confirmation Promise rejected");
          }
          confirmationResult = observation.readValue();
        }
        confirmed = confirmationResult === true;
      } catch {
        return makeResult(
          makeDecision(
            false,
            "confirmation_error",
            "confirmation callback failed before execution",
            true,
          ),
          false,
          false,
          false,
          undefined,
          "confirmation_exception",
        );
      }
      if (!confirmed) {
        return makeResult(
          makeDecision(
            false,
            "confirmation_denied",
            "confirmation did not return the exact boolean true",
            true,
          ),
          false,
          false,
          false,
        );
      }
      const revalidated = this.#prepare(
        { name: prepared.tool.name, input: prepared.input },
        { trustedArgs: prepared.trustedArgs, confirm: parsedOptions.confirm },
      );
      if (
        !isPreparedRun(revalidated) ||
        revalidated.tool !== prepared.tool ||
        this.#actionDigest(
          revalidated.tool,
          serializeAscii(revalidated.input),
        ) !== request.actionDigest
      ) {
        return makeResult(
          makeDecision(
            false,
            "internal_revalidation_failed",
            "the approved action could not be revalidated",
            true,
          ),
          false,
          false,
          false,
        );
      }
    }

    if (!confirmed) {
      return makeResult(
        makeDecision(false, "confirmation_denied", "confirmation was denied", true),
        false,
        false,
        false,
      );
    }
    const decision = makeDecision(
      true,
      "allowed",
      "allowed within registered per-argument authority",
      prepared.needsConfirmation,
    );
    let rawResult: JsonValue | Promise<JsonValue>;
    try {
      rawResult = Reflect.apply(prepared.tool.handler, undefined, [
        prepared.input,
      ]);
      // Observe genuine, non-Proxy native Promises through the captured
      // intrinsic `then`. The settled value stays in a closure rather than
      // being passed to another Promise resolver, which would assimilate a
      // hostile `then` property. Generic thenables and Proxy-wrapped Promises
      // remain unsupported result shapes.
      if (isGenuineNativePromise(rawResult)) {
        const observation = observeNativePromise(rawResult);
        if (!(await observation.completion)) {
          return makeResult(
            decision,
            true,
            false,
            false,
            undefined,
            "invocation_exception",
          );
        }
        rawResult = observation.readValue() as JsonValue;
      }
    } catch {
      return makeResult(
        decision,
        true,
        false,
        false,
        undefined,
        "invocation_exception",
      );
    }
    let approvedResult: JsonValue;
    try {
      approvedResult = snapshotJson(
        rawResult,
        { material: 0, valuesAndKeys: 0 },
        new WeakSet<object>(),
      );
    } catch {
      return makeResult(
        decision,
        true,
        true,
        false,
        undefined,
        "unsupported_result",
      );
    }
    return makeResult(decision, true, true, true, approvedResult);
  }
}

export function createGuardedToolRunner(
  registrations: readonly ToolRegistration[],
): GuardedToolRunner {
  return new GuardedToolRunner(registrations);
}
