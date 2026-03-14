/**
 * DPF Key serialization and deserialization
 *
 * Key format (matching C implementation):
 * - Byte 0: n (domain parameter)
 * - Bytes 1-16: s₀ (initial seed block)
 * - Byte 17: t₀ (initial control bit)
 * - For each layer i (1 to maxlayer):
 *   - Bytes [18*i .. 18*i+16]: sCW[i-1] (correction word)
 *   - Byte 18*i+16: tCW[i-1][0] (left correction bit)
 *   - Byte 18*i+17: tCW[i-1][1] (right correction bit)
 * - Final 16 bytes: finalblock
 */
import { Block } from './block.js';
/** A DPF key for evaluation */
export declare class DpfKey {
    /** Domain parameter (size is 2^n) */
    readonly n: number;
    /** Initial seed block */
    readonly s0: Block;
    /** Initial control bit */
    readonly t0: number;
    /** Correction words (one per layer) */
    readonly scw: Block[];
    /** Correction bits (two per layer) */
    readonly tcw: number[][];
    /** Final correction block */
    readonly finalBlock: Block;
    constructor(n: number, s0: Block, t0: number, scw: Block[], tcw: number[][], finalBlock: Block);
    /** Get the number of layers (maxlayer = n - 7) */
    maxLayer(): number;
    /** Get the key size in bytes */
    size(): number;
    /** Serialize the key to bytes */
    toBytes(): Uint8Array;
    /** Deserialize a key from bytes */
    static fromBytes(bytes: Uint8Array): DpfKey;
}
