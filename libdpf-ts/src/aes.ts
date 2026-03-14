/**
 * AES-128 encryption wrapper with browser and Node.js support
 * 
 * Provides AES-128 encryption for the DPF PRG construction.
 * Uses Web Crypto API in browsers, Node.js crypto module as fallback.
 */

import { Block } from './block';

/** Detect environment and get crypto implementation */
function getNodeCrypto(): typeof import('crypto') | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('crypto');
  } catch {
    return null;
  }
}

/** Check if running in browser with Web Crypto API */
function hasWebCrypto(): boolean {
  return typeof window !== 'undefined' && 
         window.crypto !== undefined && 
         window.crypto.subtle !== undefined;
}

/** Convert Uint8Array to ArrayBuffer for Web Crypto API compatibility */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** Cache for imported Web Crypto keys */
let webCryptoKeyCache: Map<string, CryptoKey> = new Map();

/** AES-128 key wrapper with async encryption */
export class AesKey {
    private keyBytes: Uint8Array;
    private nodeCrypto: ReturnType<typeof getNodeCrypto>;

    constructor(keyBlock: Block) {
        // Create a 128-bit key from the block
        this.keyBytes = keyBlock.toBytes();
        this.nodeCrypto = getNodeCrypto();
    }

    /** Get or create a Web Crypto key for this AES key */
    private async getWebCryptoKey(): Promise<CryptoKey> {
        const keyHex = Array.from(this.keyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        
        let cryptoKey = webCryptoKeyCache.get(keyHex);
        if (cryptoKey) {
            return cryptoKey;
        }

        cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            toArrayBuffer(this.keyBytes),
            { name: 'AES-ECB' },
            false,
            ['encrypt']
        );
        
        webCryptoKeyCache.set(keyHex, cryptoKey);
        return cryptoKey;
    }

    /** Encrypt a single block (returns new block) */
    async encryptBlock(block: Block): Promise<Block> {
        const bytes = block.toBytes();
        
        // Browser: Use Web Crypto API
        if (hasWebCrypto()) {
            const cryptoKey = await this.getWebCryptoKey();
            const encrypted = await window.crypto.subtle.encrypt(
                { name: 'AES-ECB' },
                cryptoKey,
                toArrayBuffer(bytes)
            );
            return Block.fromBytes(new Uint8Array(encrypted));
        }
        
        // Node.js fallback
        if (this.nodeCrypto) {
            const cipher = this.nodeCrypto.createCipheriv('aes-128-ecb', Buffer.from(this.keyBytes), null);
            cipher.setAutoPadding(false);
            
            const encrypted = Buffer.concat([
                cipher.update(Buffer.from(bytes)),
                cipher.final()
            ]);
            
            return Block.fromBytes(new Uint8Array(encrypted));
        }
        
        throw new Error('No crypto implementation available. Please run in a browser with Web Crypto API or in Node.js.');
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