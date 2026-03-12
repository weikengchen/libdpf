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

import { Block } from './block';

/** A DPF key for evaluation */
export class DpfKey {
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

    constructor(
        n: number,
        s0: Block,
        t0: number,
        scw: Block[],
        tcw: number[][],
        finalBlock: Block
    ) {
        this.n = n;
        this.s0 = s0;
        this.t0 = t0;
        this.scw = scw;
        this.tcw = tcw;
        this.finalBlock = finalBlock;
    }

    /** Get the number of layers (maxlayer = n - 7) */
    maxLayer(): number {
        return this.n - 7;
    }

    /** Get the key size in bytes */
    size(): number {
        const maxlayer = this.maxLayer();
        return 1 + 16 + 1 + 18 * maxlayer + 16;
    }

    /** Serialize the key to bytes */
    toBytes(): Uint8Array {
        const size = this.size();
        const bytes = new Uint8Array(size);

        bytes[0] = this.n;
        bytes.set(this.s0.toBytes(), 1);
        bytes[17] = this.t0;

        for (let i = 0; i < this.scw.length; i++) {
            const offset = 18 * (i + 1);
            bytes.set(this.scw[i].toBytes(), offset);
            bytes[offset + 16] = this.tcw[i][0];
            bytes[offset + 17] = this.tcw[i][1];
        }

        const finalOffset = 18 * (this.maxLayer() + 1);
        bytes.set(this.finalBlock.toBytes(), finalOffset);

        return bytes;
    }

    /** Deserialize a key from bytes */
    static fromBytes(bytes: Uint8Array): DpfKey {
        if (bytes.length < 18) {
            throw new Error("Key too short");
        }

        const n = bytes[0];
        const maxlayer = n - 7;
        const expectedSize = 1 + 16 + 1 + 18 * maxlayer + 16;

        if (bytes.length < expectedSize) {
            throw new Error(`Key has incorrect length: expected ${expectedSize}, got ${bytes.length}`);
        }

        const s0 = Block.fromBytes(bytes.slice(1, 17));
        const t0 = bytes[17];

        const scw: Block[] = [];
        const tcw: number[][] = [];

        for (let i = 0; i < maxlayer; i++) {
            const offset = 18 * (i + 1);
            const cw = Block.fromBytes(bytes.slice(offset, offset + 16));
            scw.push(cw);
            tcw.push([bytes[offset + 16], bytes[offset + 17]]);
        }

        const finalOffset = 18 * (maxlayer + 1);
        const finalBlock = Block.fromBytes(bytes.slice(finalOffset, finalOffset + 16));

        return new DpfKey(n, s0, t0, scw, tcw, finalBlock);
    }
}