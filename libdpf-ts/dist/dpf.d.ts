/**
 * Distributed Point Function (DPF) implementation
 *
 * Implements the core DPF algorithms from
 * "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16)
 *
 * Browser compatible - uses Web Crypto API with Node.js fallback.
 */
import { Block } from './block.js';
import { DpfKey } from './key.js';
export { DpfKey } from './key.js';
/** Default AES key values (from C implementation) */
export declare const DEFAULT_KEY_HIGH: bigint;
export declare const DEFAULT_KEY_LOW: bigint;
/** Get the default AES key block */
export declare function defaultKey(): Block;
/** DPF context for key generation and evaluation */
export declare class Dpf {
    private prg;
    constructor(key?: Block);
    /** Create a DPF context with the default key */
    static withDefaultKey(): Dpf;
    /**
     * Generate two DPF keys for a point function f where f(α) = 1 and f(x) = 0 for x ≠ α
     *
     * @param alpha - The special point where f(α) = 1
     * @param n - Domain parameter (domain size is 2^n)
     * @returns [k0, k1] - Two DPF keys for parties 0 and 1
     */
    gen(alpha: number | bigint, n: number): Promise<[DpfKey, DpfKey]>;
    /**
     * Evaluate the DPF at a single point
     *
     * @param key - The DPF key
     * @param x - The point to evaluate at
     * @returns A 128-bit block representing the evaluation result
     */
    eval(key: DpfKey, x: number | bigint): Promise<Block>;
    /**
     * Evaluate the DPF at all points in the domain
     *
     * @param key - The DPF key
     * @returns An array of 2^(n-7) blocks representing all evaluation results
     */
    evalFull(key: DpfKey): Promise<Block[]>;
}
/** Convenience function to generate DPF keys */
export declare function gen(alpha: number | bigint, n: number): Promise<[DpfKey, DpfKey]>;
/** Convenience function to evaluate DPF at a point */
export declare function evalAt(key: DpfKey, x: number | bigint): Promise<Block>;
/** Convenience function for full domain evaluation */
export declare function evalFull(key: DpfKey): Promise<Block[]>;
