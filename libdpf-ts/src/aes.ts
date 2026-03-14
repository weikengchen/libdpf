/**
 * AES-128 encryption wrapper with browser and Node.js support
 * 
 * Provides AES-128 encryption for the DPF PRG construction.
 * Uses aes-js for AES-ECB (works in all environments including Safari).
 */

import aesjs from 'aes-js';
import { Block } from './block';

/** AES-128 key wrapper with async encryption */
export class AesKey {
    private keyBytes: Uint8Array;
    private aesEcb: InstanceType<typeof aesjs.ModeOfOperation.ecb>;

    constructor(keyBlock: Block) {
        // Create a 128-bit key from the block
        this.keyBytes = keyBlock.toBytes();
        // Initialize AES-ECB mode using aes-js (works in all environments)
        this.aesEcb = new aesjs.ModeOfOperation.ecb(this.keyBytes);
    }

    /** Encrypt a single block (returns new block) */
    async encryptBlock(block: Block): Promise<Block> {
        const bytes = block.toBytes();
        
        // Use aes-js for AES-ECB encryption (works in all environments including Safari)
        const encrypted = this.aesEcb.encrypt(bytes);
        return Block.fromBytes(new Uint8Array(encrypted));
    }

    /** Encrypt two blocks */
    async encryptTwoBlocks(block0: Block, block1: Block): Promise<[Block, Block]> {
        return Promise.all([
            this.encryptBlock(block0),
            this.encryptBlock(block1)
        ]);
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
    async generate(input: Block): Promise<[Block, Block, number, number]> {
        // Zero the LSB
        let stash0 = input.setLsbZero();
        let stash1 = stash0.reverseLsb();

        // Encrypt both blocks
        [stash0, stash1] = await this.aesKey.encryptTwoBlocks(stash0, stash1);

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