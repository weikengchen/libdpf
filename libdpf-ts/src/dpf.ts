/**
 * Distributed Point Function (DPF) implementation
 * 
 * Implements the core DPF algorithms from
 * "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16)
 * 
 * Browser compatible - uses Web Crypto API with Node.js fallback.
 */

import { Block } from './block';
import { Prg } from './aes';
import { DpfKey } from './key';

// Re-export DpfKey for convenience
export { DpfKey } from './key';

/** Get a specific bit from an integer (bit b from position n) */
function getBit(x: number | bigint, n: number, b: number): number {
    const bigX = BigInt(x);
    return Number((bigX >> BigInt(n - b)) & 1n);
}

/** Default AES key values (from C implementation) */
export const DEFAULT_KEY_HIGH = BigInt(597349);
export const DEFAULT_KEY_LOW = BigInt(121379);

/** Get the default AES key block */
export function defaultKey(): Block {
    return new Block(DEFAULT_KEY_HIGH, DEFAULT_KEY_LOW);
}

/**
 * Get random bytes - works in both browser and Node.js
 * Uses Web Crypto API in browsers, Node.js crypto as fallback
 */
function getRandomBytes(size: number): Uint8Array {
    // Browser: Use Web Crypto API
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
        const bytes = new Uint8Array(size);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }
    
    // Node.js fallback
    try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        return require('crypto').randomBytes(size);
    } catch {
        throw new Error('No secure random implementation available. Please run in a browser with Web Crypto API or in Node.js.');
    }
}

/** DPF context for key generation and evaluation */
export class Dpf {
    private prg: Prg;

    constructor(key?: Block) {
        this.prg = new Prg(key ?? defaultKey());
    }

    /** Create a DPF context with the default key */
    static withDefaultKey(): Dpf {
        return new Dpf(defaultKey());
    }

    /**
     * Generate two DPF keys for a point function f where f(α) = 1 and f(x) = 0 for x ≠ α
     * 
     * @param alpha - The special point where f(α) = 1
     * @param n - Domain parameter (domain size is 2^n)
     * @returns [k0, k1] - Two DPF keys for parties 0 and 1
     */
    async gen(alpha: number | bigint, n: number): Promise<[DpfKey, DpfKey]> {
        const alphaBig = BigInt(alpha);
        const maxlayer = n - 7;

        // Arrays to track seeds and control bits through the tree
        const s: Block[][] = [];
        const t: number[][] = [];

        for (let i = 0; i <= maxlayer; i++) {
            s.push([Block.zero(), Block.zero()]);
            t.push([0, 0]);
        }

        // Correction words
        const scw: Block[] = [];
        const tcw: number[][] = [];
        for (let i = 0; i < maxlayer; i++) {
            scw.push(Block.zero());
            tcw.push([0, 0]);
        }

        // Initialize random seeds for both parties (browser compatible)
        const s0Bytes = getRandomBytes(16);
        const s1Bytes = getRandomBytes(16);
        s[0][0] = Block.fromBytes(s0Bytes);
        s[0][1] = Block.fromBytes(s1Bytes);

        // Set initial control bits
        t[0][0] = s[0][0].lsb();
        t[0][1] = t[0][0] ^ 1;

        // Zero LSBs of initial seeds
        s[0][0] = s[0][0].setLsbZero();
        s[0][1] = s[0][1].setLsbZero();

        // Iterate through layers
        for (let i = 1; i <= maxlayer; i++) {
            // PRG expand for both parties
            const [s0L, s0R, t0L, t0R] = await this.prg.generate(s[i - 1][0]);
            const [s1L, s1R, t1L, t1R] = await this.prg.generate(s[i - 1][1]);

            // Determine keep/lose based on alpha's bit at this position
            const alphaBit = getBit(alphaBig, n, i);
            const keep = alphaBit === 0 ? 0 : 1;
            const lose = 1 - keep;

            const s0 = [s0L, s0R];
            const s1 = [s1L, s1R];
            const t0 = [t0L, t0R];
            const t1 = [t1L, t1R];

            // Correction word for seeds
            scw[i - 1] = s0[lose].xor(s1[lose]);

            // Correction bits
            tcw[i - 1][0] = t0[0] ^ t1[0] ^ alphaBit ^ 1;
            tcw[i - 1][1] = t0[1] ^ t1[1] ^ alphaBit;

            // Propagate for party 0
            if (t[i - 1][0] === 1) {
                s[i][0] = s0[keep].xor(scw[i - 1]);
                t[i][0] = t0[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][0] = s0[keep];
                t[i][0] = t0[keep];
            }

            // Propagate for party 1
            if (t[i - 1][1] === 1) {
                s[i][1] = s1[keep].xor(scw[i - 1]);
                t[i][1] = t1[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][1] = s1[keep];
                t[i][1] = t1[keep];
            }
        }

        // Compute final correction block
        let finalBlock = Block.zero().reverseLsb();

        // Shift to set the appropriate bit based on alpha & 127
        const shift = Number(alphaBig & 127n);
        finalBlock = finalBlock.leftShift(shift);

        // Reverse LSB
        finalBlock = finalBlock.reverseLsb();

        // XOR with final seeds
        finalBlock = finalBlock.xor(s[maxlayer][0]);
        finalBlock = finalBlock.xor(s[maxlayer][1]);

        // Create keys for both parties
        const k0 = new DpfKey(n, s[0][0], t[0][0], [...scw], [...tcw], finalBlock);
        const k1 = new DpfKey(n, s[0][1], t[0][1], [...scw], [...tcw], finalBlock);

        return [k0, k1];
    }

    /**
     * Evaluate the DPF at a single point
     * 
     * @param key - The DPF key
     * @param x - The point to evaluate at
     * @returns A 128-bit block representing the evaluation result
     */
    async eval(key: DpfKey, x: number | bigint): Promise<Block> {
        const xBig = BigInt(x);
        const maxlayer = key.maxLayer();

        // Current seed and control bit
        let s = key.s0;
        let t = key.t0;

        // Traverse the tree
        for (let i = 1; i <= maxlayer; i++) {
            const [sL, sR, tL, tR] = await this.prg.generate(s);

            // Apply correction if needed
            let sLCorr = sL;
            let sRCorr = sR;
            let tLCorr = tL;
            let tRCorr = tR;

            if (t === 1) {
                sLCorr = sL.xor(key.scw[i - 1]);
                sRCorr = sR.xor(key.scw[i - 1]);
                tLCorr = tL ^ key.tcw[i - 1][0];
                tRCorr = tR ^ key.tcw[i - 1][1];
            }

            // Choose left or right based on x's bit
            const xBit = getBit(xBig, key.n, i);
            if (xBit === 0) {
                s = sLCorr;
                t = tLCorr;
            } else {
                s = sRCorr;
                t = tRCorr;
            }
        }

        // Apply final corrections
        let res = s;
        if (t === 1) {
            res = res.reverseLsb();
        }
        if (t === 1) {
            res = res.xor(key.finalBlock);
        }

        return res;
    }

    /**
     * Evaluate the DPF at all points in the domain
     * 
     * @param key - The DPF key
     * @returns An array of 2^(n-7) blocks representing all evaluation results
     */
    async evalFull(key: DpfKey): Promise<Block[]> {
        const maxlayer = key.maxLayer();
        const maxlayeritem = 1 << maxlayer;

        // Two layers for ping-pong evaluation
        const s: Block[][] = [
            new Array(maxlayeritem).fill(null).map(() => Block.zero()),
            new Array(maxlayeritem).fill(null).map(() => Block.zero())
        ];
        const t: number[][] = [
            new Array(maxlayeritem).fill(0),
            new Array(maxlayeritem).fill(0)
        ];

        // Initialize
        s[0][0] = key.s0;
        t[0][0] = key.t0;

        let curlayer = 1;

        // Traverse the tree breadth-first
        for (let i = 1; i <= maxlayer; i++) {
            const itemnumber = 1 << (i - 1);
            for (let j = 0; j < itemnumber; j++) {
                const [sL, sR, tL, tR] = await this.prg.generate(s[1 - curlayer][j]);

                // Apply correction if needed
                let sLCorr = sL;
                let sRCorr = sR;
                let tLCorr = tL;
                let tRCorr = tR;

                if (t[1 - curlayer][j] === 1) {
                    sLCorr = sL.xor(key.scw[i - 1]);
                    sRCorr = sR.xor(key.scw[i - 1]);
                    tLCorr = tL ^ key.tcw[i - 1][0];
                    tRCorr = tR ^ key.tcw[i - 1][1];
                }

                // Store results
                s[curlayer][2 * j] = sLCorr;
                t[curlayer][2 * j] = tLCorr;
                s[curlayer][2 * j + 1] = sRCorr;
                t[curlayer][2 * j + 1] = tRCorr;
            }
            curlayer = 1 - curlayer;
        }

        // Compute final results
        const itemnumber = maxlayeritem;
        const res: Block[] = [];

        for (let j = 0; j < itemnumber; j++) {
            let block = s[1 - curlayer][j];

            if (t[1 - curlayer][j] === 1) {
                block = block.reverseLsb();
            }
            if (t[1 - curlayer][j] === 1) {
                block = block.xor(key.finalBlock);
            }

            res.push(block);
        }

        return res;
    }
}

/** Convenience function to generate DPF keys */
export async function gen(alpha: number | bigint, n: number): Promise<[DpfKey, DpfKey]> {
    const dpf = Dpf.withDefaultKey();
    return dpf.gen(alpha, n);
}

/** Convenience function to evaluate DPF at a point */
export async function evalAt(key: DpfKey, x: number | bigint): Promise<Block> {
    const dpf = Dpf.withDefaultKey();
    return dpf.eval(key, x);
}

/** Convenience function for full domain evaluation */
export async function evalFull(key: DpfKey): Promise<Block[]> {
    const dpf = Dpf.withDefaultKey();
    return dpf.evalFull(key);
}