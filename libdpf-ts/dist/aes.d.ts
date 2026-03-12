/**
 * AES-128 encryption wrapper using Node.js crypto module
 *
 * Provides AES-128 encryption for the DPF PRG construction.
 */
import { Block } from './block';
/** AES-128 key wrapper */
export declare class AesKey {
    private key;
    constructor(keyBlock: Block);
    /** Encrypt a single block in-place (returns new block) */
    encryptBlock(block: Block): Block;
    /** Encrypt two blocks */
    encryptTwoBlocks(block0: Block, block1: Block): [Block, Block];
}
/** PRG (Pseudorandom Generator) for DPF */
export declare class Prg {
    private aesKey;
    constructor(key: Block);
    /**
     * Generate pseudorandom outputs from a seed block
     *
     * @param input - The seed block (LSB will be zeroed before use)
     * @returns [output1, output2, bit1, bit2] - Two output blocks and two control bits
     */
    generate(input: Block): [Block, Block, number, number];
}
