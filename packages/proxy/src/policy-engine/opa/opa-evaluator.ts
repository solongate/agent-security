// OPA Evaluator: loads and evaluates WASM-compiled Rego policies at runtime.
import { gunzipSync } from 'node:zlib';
import type { PolicyDecision, PolicyEffect, ExecutionRequest } from '../../core/index.js';
import { DEFAULT_POLICY_EFFECT } from '../../core/index.js';
import { toOpaInput, type OpaDecision } from './request-adapter.js';

// Dynamic import for opa-wasm (CommonJS module)
let loadPolicyFn: ((wasmBytes: BufferSource, memoryDescriptor?: WebAssembly.MemoryDescriptor) => Promise<OpaPolicy>) | null = null;

interface OpaPolicy {
  evaluate(input: unknown): Array<{ result: OpaDecision }>;
  setData(data: unknown): void;
}

async function getLoadPolicy() {
  if (!loadPolicyFn) {
    // @open-policy-agent/opa-wasm is CommonJS; use dynamic import
    const mod = await import('@open-policy-agent/opa-wasm');
    loadPolicyFn = (mod as any).loadPolicy || (mod as any).default?.loadPolicy;
    if (!loadPolicyFn) {
      throw new Error('Could not find loadPolicy in @open-policy-agent/opa-wasm');
    }
  }
  return loadPolicyFn;
}

// Extracts the policy.wasm file from an OPA bundle (.tar.gz).
// OPA bundles are gzipped tar archives containing /policy.wasm.
function extractWasmFromBundle(bundle: Buffer): Buffer {
  // Check if it's a gzip file (magic bytes 1f 8b)
  if (bundle[0] === 0x1f && bundle[1] === 0x8b) {
    const decompressed = gunzipSync(bundle);
    // Parse tar to find policy.wasm
    return extractFromTar(decompressed, '/policy.wasm');
  }
  // Check if it's raw WASM (magic bytes 00 61 73 6d)
  if (bundle[0] === 0x00 && bundle[1] === 0x61 && bundle[2] === 0x73 && bundle[3] === 0x6d) {
    return bundle;
  }
  throw new Error('Unknown bundle format: expected .tar.gz or .wasm');
}

// Minimal tar parser — extracts a single file from a tar archive.
// tar format: 512-byte header blocks followed by file data (512-byte aligned).
function extractFromTar(tar: Buffer, targetPath: string): Buffer {
  let offset = 0;
  const target = targetPath.replace(/^\//, ''); // strip leading /

  while (offset < tar.length - 512) {
    // Read filename from header (first 100 bytes, null-terminated)
    const nameEnd = tar.indexOf(0, offset);
    const name = tar.subarray(offset, Math.min(nameEnd, offset + 100)).toString('utf-8');

    if (!name || name.length === 0) break; // end of archive

    // Read file size from header (octal, bytes 124-136)
    const sizeStr = tar.subarray(offset + 124, offset + 136).toString('utf-8').trim();
    const size = parseInt(sizeStr, 8) || 0;

    // Move past header
    offset += 512;

    // Check if this is our target file
    if (name === target || name === `./${target}` || name.endsWith(target)) {
      return Buffer.from(tar.subarray(offset, offset + size));
    }

    // Skip file data (aligned to 512 bytes)
    offset += Math.ceil(size / 512) * 512;
  }

  throw new Error(`File "${targetPath}" not found in tar archive`);
}

// OPA WASM-based policy evaluator.
// This is the PDP (Policy Decision Point) as defined by NIST SP 800-207.
// It loads a pre-compiled OPA WASM bundle and evaluates tool call requests
// with sub-millisecond latency.
// Usage:
//   const evaluator = new OpaEvaluator();
//   await evaluator.loadBundle(wasmBytes);
//   const decision = evaluator.evaluate(request);
export class OpaEvaluator {
  private policy: OpaPolicy | null = null;
  private initialized = false;

  // Loads a compiled OPA WASM bundle.
  // The bundle can be:
  // - A .tar.gz file produced by `opa build -t wasm` (extracts policy.wasm automatically)
  // - Raw .wasm bytes
  // @param wasmBundle - Buffer containing the WASM bundle
  async loadBundle(wasmBundle: BufferSource): Promise<void> {
    const loadPolicy = await getLoadPolicy();
    const buf = Buffer.from(wasmBundle as ArrayBuffer);
    const wasmBytes = extractWasmFromBundle(buf);
    this.policy = await loadPolicy(wasmBytes as unknown as BufferSource, { initial: 5 });
    this.initialized = true;
  }

  // Loads raw WASM bytes (not a tar.gz bundle).
  // Use this when you have the extracted .wasm file directly.
  async loadWasm(wasmBytes: BufferSource): Promise<void> {
    const loadPolicy = await getLoadPolicy();
    this.policy = await loadPolicy(wasmBytes, { initial: 5 });
    this.initialized = true;
  }

  // Evaluates an execution request against the loaded OPA policy.
  // Returns a PolicyDecision matching the same interface as the legacy evaluator,
  // ensuring full backward compatibility.
  evaluate(request: ExecutionRequest): PolicyDecision {
    if (!this.policy || !this.initialized) {
      throw new Error('OPA policy not loaded. Call loadBundle() or loadWasm() first.');
    }

    const startTime = performance.now();
    const input = toOpaInput(request);
    const results = this.policy.evaluate(input);
    const endTime = performance.now();
    const decision = results?.[0]?.result;

    if (!decision || !decision.effect) {
      // No decision from OPA — fall back to default deny
      return {
        effect: DEFAULT_POLICY_EFFECT as PolicyEffect,
        matchedRule: null,
        reason: 'No matching policy rule found. Default action: DENY.',
        timestamp: new Date().toISOString(),
        evaluationTimeMs: endTime - startTime,
      };
    }

    return {
      effect: decision.effect as PolicyEffect,
      matchedRule: decision.matched_rule ? { id: decision.matched_rule } as any : null,
      reason: decision.reason,
      timestamp: new Date().toISOString(),
      evaluationTimeMs: endTime - startTime,
    };
  }

  // Whether the evaluator has a loaded policy.
  isReady(): boolean {
    return this.initialized && this.policy !== null;
  }

  // Sets additional data for the OPA policy.
  // This can be used to provide external data documents to the policy.
  setData(data: unknown): void {
    if (!this.policy) {
      throw new Error('OPA policy not loaded.');
    }
    this.policy.setData(data);
  }
}