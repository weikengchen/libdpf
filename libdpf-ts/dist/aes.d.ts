/**
 * AES-128 encryption wrapper with browser and Node.js support
 *
 * Provides AES-128 encryption for the DPF PRG construction.
 * Uses Web Crypto API in browsers, Node.js crypto module as fallback.
 */
import { Block } from './block';
/** AES-128 key wrapper with async encryption */
export declare class AesKey {
    private keyBytes;
    private nodeCrypto;
    constructor(keyBlock: Block);
    /** Get or create a Web Crypto key for this AES key */
    private getWebCryptoKey;
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
