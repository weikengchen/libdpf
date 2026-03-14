/**
 * Tests for DPF implementation
 */

import { Block } from '../block.js';
import { Dpf, DpfKey, gen, evalAt, evalFull } from '../dpf.js';

function assertEqual<T>(actual: T, expected: T, message?: string): void {
    if (actual !== expected) {
        throw new Error(message ?? `Expected ${expected}, got ${actual}`);
    }
}

function assertBlockEqual(actual: Block, expected: Block, message?: string): void {
    if (!actual.equals(expected)) {
        throw new Error(message ?? `Expected ${expected.toString()}, got ${actual.toString()}`);
    }
}

function assertBlockNotZero(block: Block, message?: string): void {
    if (block.isZero()) {
        throw new Error(message ?? "Expected non-zero block");
    }
}

function assertBlockZero(block: Block, message?: string): void {
    if (!block.isZero()) {
        throw new Error(message ?? `Expected zero block, got ${block.toString()}`);
    }
}

// Test Block operations
function testBlockXor(): void {
    const a = new Block(0xFFFFn, 0xAAAAn);
    const b = new Block(0x0000n, 0x5555n);
    const result = a.xor(b);
    assertEqual(result.low, 0xFFFFn, "Block XOR low mismatch");
    assertEqual(result.high, 0xFFFFn, "Block XOR high mismatch");
    console.log("  ✓ testBlockXor passed");
}

function testBlockLsb(): void {
    const a = new Block(0n, 0n);
    assertEqual(a.lsb(), 0, "LSB of zero block should be 0");

    const b = new Block(0n, 1n);
    assertEqual(b.lsb(), 1, "LSB of block with low=1 should be 1");

    const c = new Block(1n, 0n);
    assertEqual(c.lsb(), 0, "LSB of block with high=1 should be 0");
    console.log("  ✓ testBlockLsb passed");
}

function testBlockReverseLsb(): void {
    const a = new Block(0n, 0n);
    assertEqual(a.reverseLsb().lsb(), 1, "Reverse LSB of 0 should be 1");

    const b = new Block(0n, 1n);
    assertEqual(b.reverseLsb().lsb(), 0, "Reverse LSB of 1 should be 0");
    console.log("  ✓ testBlockReverseLsb passed");
}

function testBlockSetLsbZero(): void {
    const a = new Block(0n, 1n);
    assertEqual(a.setLsbZero().lsb(), 0, "setLsbZero should make LSB 0");

    const b = new Block(0n, 0n);
    assertEqual(b.setLsbZero().lsb(), 0, "setLsbZero on zero block should stay 0");
    console.log("  ✓ testBlockSetLsbZero passed");
}

function testBlockLeftShift(): void {
    // Test shift within low
    const a = new Block(0n, 1n);
    const shifted = a.leftShift(1);
    assertEqual(shifted.low, 2n, "Left shift 1 of low=1 should give low=2");
    assertEqual(shifted.high, 0n, "Left shift 1 of low=1 should give high=0");

    // Test shift crossing boundary
    const b = new Block(0n, 1n);
    const shifted2 = b.leftShift(64);
    assertEqual(shifted2.low, 0n, "Left shift 64 of low=1 should give low=0");
    assertEqual(shifted2.high, 1n, "Left shift 64 of low=1 should give high=1");
    console.log("  ✓ testBlockLeftShift passed");
}

function testBlockBytesRoundtrip(): void {
    const original = new Block(0x123456789ABCDEF0n, 0xFEDCBA9876543210n);
    const bytes = original.toBytes();
    const restored = Block.fromBytes(bytes);
    assertBlockEqual(restored, original, "Block bytes roundtrip failed");
    console.log("  ✓ testBlockBytesRoundtrip passed");
}

// Test DPF operations (now async)
async function testGenBasic(): Promise<void> {
    const dpf = Dpf.withDefaultKey();
    const [k0, k1] = await dpf.gen(26943, 16);

    assertEqual(k0.n, 16, "k0.n should be 16");
    assertEqual(k1.n, 16, "k1.n should be 16");
    assertEqual(k0.scw.length, k0.maxLayer(), "scw length mismatch");
    assertEqual(k1.scw.length, k1.maxLayer(), "scw length mismatch");
    console.log("  ✓ testGenBasic passed");
}

async function testEvalXorProperty(): Promise<void> {
    const dpf = Dpf.withDefaultKey();
    const alpha = 26943;
    const n = 16;

    const [k0, k1] = await dpf.gen(alpha, n);

    // Evaluate at alpha - should get non-zero result when XOR'd
    const r0 = await dpf.eval(k0, alpha);
    const r1 = await dpf.eval(k1, alpha);
    const xorResult = r0.xor(r1);

    assertBlockNotZero(xorResult, "XOR at alpha should be non-zero");
    console.log("  ✓ testEvalXorProperty passed");
}

async function testEvalZeroAtOtherPoints(): Promise<void> {
    const dpf = Dpf.withDefaultKey();
    const alpha = 26943;
    const n = 16;

    const [k0, k1] = await dpf.gen(alpha, n);

    // Evaluate at different points - should get zero when XOR'd
    const alphaBlock = Math.floor(alpha / 128);
    const testPoints = [0, 1000, 60000];

    for (const x of testPoints) {
        const xBlock = Math.floor(x / 128);
        if (xBlock !== alphaBlock) {
            const r0 = await dpf.eval(k0, x);
            const r1 = await dpf.eval(k1, x);
            const xorResult = r0.xor(r1);
            assertBlockZero(xorResult, `XOR at x=${x} (block ${xBlock}) with alpha=${alpha} (block ${alphaBlock}) should be zero`);
        }
    }
    console.log("  ✓ testEvalZeroAtOtherPoints passed");
}

async function testEvalFull(): Promise<void> {
    const dpf = Dpf.withDefaultKey();
    const alpha = 26943;
    const n = 16;

    const [k0, k1] = await dpf.gen(alpha, n);

    const res0 = await dpf.evalFull(k0);
    const res1 = await dpf.evalFull(k1);

    const expectedLen = 1 << (n - 7);
    assertEqual(res0.length, expectedLen, "evalFull result length mismatch for k0");
    assertEqual(res1.length, expectedLen, "evalFull result length mismatch for k1");

    // Check that XOR results match point-by-point evaluation
    for (let i = 0; i < res0.length; i++) {
        const xorResult = res0[i].xor(res1[i]);
        const blockStart = i * 128;
        const blockEnd = blockStart + 128;

        if (alpha >= blockStart && alpha < blockEnd) {
            assertBlockNotZero(xorResult, `Block ${i} containing alpha should be non-zero`);
        } else {
            assertBlockZero(xorResult, `Block ${i} not containing alpha should be zero`);
        }
    }
    console.log("  ✓ testEvalFull passed");
}

async function testKeySerialization(): Promise<void> {
    const dpf = Dpf.withDefaultKey();
    const alpha = 12345;
    const n = 16;

    const [k0, k1] = await dpf.gen(alpha, n);

    // Serialize and deserialize
    const k0Bytes = k0.toBytes();
    const k0Restored = DpfKey.fromBytes(k0Bytes);
    const k1Bytes = k1.toBytes();
    const k1Restored = DpfKey.fromBytes(k1Bytes);

    // Evaluations should match
    for (const x of [0, alpha, 50000]) {
        const r0Orig = await dpf.eval(k0, x);
        const r0Rest = await dpf.eval(k0Restored, x);
        const r1Orig = await dpf.eval(k1, x);
        const r1Rest = await dpf.eval(k1Restored, x);

        assertBlockEqual(r0Orig, r0Rest, `k0 evaluation mismatch at x=${x}`);
        assertBlockEqual(r1Orig, r1Rest, `k1 evaluation mismatch at x=${x}`);
    }
    console.log("  ✓ testKeySerialization passed");
}

async function testConvenienceFunctions(): Promise<void> {
    const alpha = 12345;
    const n = 16;

    const [k0, k1] = await gen(alpha, n);
    const r0 = await evalAt(k0, alpha);
    const r1 = await evalAt(k1, alpha);

    assertBlockNotZero(r0.xor(r1), "Convenience function: XOR at alpha should be non-zero");
    console.log("  ✓ testConvenienceFunctions passed");
}

// Run all tests
export async function runTests(): Promise<void> {
    console.log("\n=== Block Tests ===");
    testBlockXor();
    testBlockLsb();
    testBlockReverseLsb();
    testBlockSetLsbZero();
    testBlockLeftShift();
    testBlockBytesRoundtrip();

    console.log("\n=== DPF Tests ===");
    await testGenBasic();
    await testEvalXorProperty();
    await testEvalZeroAtOtherPoints();
    await testEvalFull();
    await testKeySerialization();
    await testConvenienceFunctions();

    console.log("\n✅ All tests passed!\n");
}

// Run tests when executed directly
runTests().catch((err) => {
    console.error("Test failed:", err);
    process.exit(1);
});