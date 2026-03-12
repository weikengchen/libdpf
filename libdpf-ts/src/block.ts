/**
 * 128-bit block operations for DPF
 * 
 * Uses BigInt for 128-bit arithmetic. Memory layout matches the C implementation
 * where the block is stored as two 64-bit values: low (bits 0-63) and high (bits 64-127).
 */

/** 128-bit block represented as two 64-bit BigInt values */
export class Block {
    /** High 64 bits (bits 64-127) */
    readonly high: bigint;
    /** Low 64 bits (bits 0-63) */
    readonly low: bigint;

    /** Mask for 64-bit values */
    private static readonly MASK64 = BigInt("0xFFFFFFFFFFFFFFFF");

    constructor(high: bigint | number, low: bigint | number) {
        this.high = BigInt(high) & Block.MASK64;
        this.low = BigInt(low) & Block.MASK64;
    }

    /** Create a zero block */
    static zero(): Block {
        return new Block(0n, 0n);
    }

    /** Create a block from a 16-byte Uint8Array */
    static fromBytes(bytes: Uint8Array): Block {
        if (bytes.length !== 16) {
            throw new Error("Block requires exactly 16 bytes");
        }
        const dataView = new DataView(bytes.buffer, bytes.byteOffset, 16);
        const low = dataView.getBigUint64(0, true); // little-endian
        const high = dataView.getBigUint64(8, true);
        return new Block(high, low);
    }

    /** Convert block to a 16-byte Uint8Array */
    toBytes(): Uint8Array {
        const bytes = new Uint8Array(16);
        const dataView = new DataView(bytes.buffer);
        dataView.setBigUint64(0, this.low, true); // little-endian
        dataView.setBigUint64(8, this.high, true);
        return bytes;
    }

    /** XOR this block with another */
    xor(other: Block): Block {
        return new Block(this.high ^ other.high, this.low ^ other.low);
    }

    /** Get the least significant bit */
    lsb(): number {
        return Number(this.low & 1n);
    }

    /** Check if two blocks are equal */
    equals(other: Block): boolean {
        return this.low === other.low && this.high === other.high;
    }

    /** Check if two blocks are unequal */
    notEquals(other: Block): boolean {
        return !this.equals(other);
    }

    /** Check if this is the zero block */
    isZero(): boolean {
        return this.low === 0n && this.high === 0n;
    }

    /** Reverse the LSB of the block */
    reverseLsb(): Block {
        return new Block(this.high, this.low ^ 1n);
    }

    /** Set the LSB to zero */
    setLsbZero(): Block {
        if (this.lsb() === 1) {
            return this.reverseLsb();
        }
        return this;
    }

    /** Left shift the entire 128-bit block by n bits (0-127) */
    leftShift(n: number): Block {
        if (n === 0) return this;
        if (n >= 128) return Block.zero();

        const shift = BigInt(n);

        if (n >= 64) {
            // Shift crosses boundary - all low bits go to high
            return new Block(this.low << (shift - 64n), 0n);
        } else {
            // Normal case: both parts have bits
            const newLow = (this.low << shift) & Block.MASK64;
            const newHigh = ((this.high << shift) | (this.low >> (64n - shift))) & Block.MASK64;
            return new Block(newHigh, newLow);
        }
    }

    /** Right shift the entire 128-bit block by n bits (0-127) */
    rightShift(n: number): Block {
        if (n === 0) return this;
        if (n >= 128) return Block.zero();

        const shift = BigInt(n);

        if (n >= 64) {
            return new Block(0n, this.high >> (shift - 64n));
        } else {
            const newLow = (this.low >> shift) | ((this.high << (64n - shift)) & Block.MASK64);
            const newHigh = this.high >> shift;
            return new Block(newHigh, newLow);
        }
    }

    /** Double the block (left shift by 1) */
    double(): Block {
        return this.leftShift(1);
    }

    /** Convert to binary string representation (for debugging) */
    toBinaryString(): string {
        let result = "";
        // Low bits first
        for (let i = 0n; i < 64n; i++) {
            result += ((this.low >> i) & 1n).toString();
        }
        // High bits
        for (let i = 0n; i < 64n; i++) {
            result += ((this.high >> i) & 1n).toString();
        }
        return result;
    }

    /** String representation */
    toString(): string {
        return `Block(${this.high.toString(16)}, ${this.low.toString(16)})`;
    }
}