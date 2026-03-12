/**
 * 128-bit block operations for DPF
 *
 * Uses BigInt for 128-bit arithmetic. Memory layout matches the C implementation
 * where the block is stored as two 64-bit values: low (bits 0-63) and high (bits 64-127).
 */
/** 128-bit block represented as two 64-bit BigInt values */
export declare class Block {
    /** High 64 bits (bits 64-127) */
    readonly high: bigint;
    /** Low 64 bits (bits 0-63) */
    readonly low: bigint;
    /** Mask for 64-bit values */
    private static readonly MASK64;
    constructor(high: bigint | number, low: bigint | number);
    /** Create a zero block */
    static zero(): Block;
    /** Create a block from a 16-byte Uint8Array */
    static fromBytes(bytes: Uint8Array): Block;
    /** Convert block to a 16-byte Uint8Array */
    toBytes(): Uint8Array;
    /** XOR this block with another */
    xor(other: Block): Block;
    /** Get the least significant bit */
    lsb(): number;
    /** Check if two blocks are equal */
    equals(other: Block): boolean;
    /** Check if two blocks are unequal */
    notEquals(other: Block): boolean;
    /** Check if this is the zero block */
    isZero(): boolean;
    /** Reverse the LSB of the block */
    reverseLsb(): Block;
    /** Set the LSB to zero */
    setLsbZero(): Block;
    /** Left shift the entire 128-bit block by n bits (0-127) */
    leftShift(n: number): Block;
    /** Right shift the entire 128-bit block by n bits (0-127) */
    rightShift(n: number): Block;
    /** Double the block (left shift by 1) */
    double(): Block;
    /** Convert to binary string representation (for debugging) */
    toBinaryString(): string;
    /** String representation */
    toString(): string;
}
