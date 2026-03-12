/**
 * AES-128 encryption wrapper using Node.js crypto module
 * 
 * Provides AES-128 encryption for the DPF PRG construction.
 */

import * as crypto from 'crypto';
import { Block } from './block';

/** AES-128 key wrapper */
export class AesKey {
    private key: Buffer;

    constructor(keyBlock: Block) {
        // Create a 128-bit key from the block
        this.key = Buffer.from(keyBlock.toBytes());
    }

    /** Encrypt a single block in-place (returns new block) */
    encryptBlock(block: Block): Block {
        const bytes = block.toBytes();
        
        // Use AES-128-ECB (no IV needed for single block encryption)
        const cipher = crypto.createCipheriv('aes-128-ecb', this.key, null);
        cipher.setAutoPadding(false);
        
        const encrypted = Buffer.concat([
            cipher.update(Buffer.from(bytes)),
            cipher.final()
        ]);
        
        return Block.fromBytes(new Uint8Array(encrypted));
    }

    /** Encrypt two blocks */
    encryptTwoBlocks(block0: Block, block1: Block): [Block, Block] {
        return [this.encryptBlock(block0), this.encryptBlock(block1)];
    }
}

/** PRG (Pseudorandom Generator) for DPF */
export class Prg {
    private aesKey: AesKey;

    constructor(key: Block) {
        this.aesKey = new AesKey(key);
    }

    /**
     * Generate pseudorandom outputs from a seed block
     * 
     * @param input - The seed block (LSB will be zeroed before use)
     * @returns [output1, output2, bit1, bit2] - Two output blocks and two control bits
     */
    generate(input: Block): [Block, Block, number, number] {
        // Zero the LSB
        let stash0 = input.setLsbZero();
        let stash1 = stash0.reverseLsb();

        // Encrypt both blocks
        [stash0, stash1] = this.aesKey.encryptTwoBlocks(stash0, stash1);

        // XOR with input
        const inputZeroed = input.setLsbZero();
        stash0 = stash0.xor(inputZeroed);
        stash1 = stash1.xor(inputZeroed);
        stash1 = stash1.reverseLsb();

        // Extract bits
        const bit1 = stash0.lsb();
        const bit2 = stash1.lsb();

        // Zero LSBs in outputs
        const output1 = stash0.setLsbZero();
        const output2 = stash1.setLsbZero();

        return [output1, output2, bit1, bit2];
    }
}