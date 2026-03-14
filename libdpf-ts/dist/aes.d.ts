/**
 * AES-128 encryption wrapper with browser and Node.js support
 *
 * Provides AES-128 encryption for the DPF PRG construction.
 * Uses aes-js for AES-ECB (works in all environments including Safari).
 */
import { Block } from './block.js';
/** AES-128 key wrapper with async encryption */
export declare class AesKey {
    private keyBytes;
    private aesEcb;
    constructor(keyBlock: Block);
    /** Encrypt a single block (returns new block) */
    encryptBlock(block: Block): Promise<Block>;
    /** Encrypt two blocks */
    encryptTwoBlocks(block0: Block, block1: Block): Promise<[Block, Block]>;
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
    generate(input: Block): Promise<[Block, Block, number, number]>;
}
