/**
 * AES-128 encryption wrapper with browser and Node.js support
 *
 * Provides AES-128 encryption for the DPF PRG construction.
 * Uses aes-js for AES-ECB (works in all environments including Safari).
 */
import aesjs from 'aes-js';
import { Block } from './block.js';
/** AES-128 key wrapper with async encryption */
export class AesKey {
    constructor(keyBlock) {
        // Create a 128-bit key from the block
        this.keyBytes = keyBlock.toBytes();
        // Initialize AES-ECB mode using aes-js (works in all environments)
        this.aesEcb = new aesjs.ModeOfOperation.ecb(this.keyBytes);
    }
    /** Encrypt a single block (returns new block) */
    async encryptBlock(block) {
        const bytes = block.toBytes();
        // Use aes-js for AES-ECB encryption (works in all environments including Safari)
        const encrypted = this.aesEcb.encrypt(bytes);
        return Block.fromBytes(new Uint8Array(encrypted));
    }
    /** Encrypt two blocks */
    async encryptTwoBlocks(block0, block1) {
        return Promise.all([
            this.encryptBlock(block0),
            this.encryptBlock(block1)
        ]);
    }
}
/** PRG (Pseudorandom Generator) for DPF */
export class Prg {
    constructor(key) {
        this.aesKey = new AesKey(key);
    }
    /**
     * Generate pseudorandom outputs from a seed block
     *
     * @param input - The seed block (LSB will be zeroed before use)
     * @returns [output1, output2, bit1, bit2] - Two output blocks and two control bits
     */
    async generate(input) {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWVzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2Flcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7R0FLRztBQUVILE9BQU8sS0FBSyxNQUFNLFFBQVEsQ0FBQztBQUMzQixPQUFPLEVBQUUsS0FBSyxFQUFFLE1BQU0sWUFBWSxDQUFDO0FBRW5DLGdEQUFnRDtBQUNoRCxNQUFNLE9BQU8sTUFBTTtJQUlmLFlBQVksUUFBZTtRQUN2QixzQ0FBc0M7UUFDdEMsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUMsT0FBTyxFQUFFLENBQUM7UUFDbkMsbUVBQW1FO1FBQ25FLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxLQUFLLENBQUMsZUFBZSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUM7SUFDL0QsQ0FBQztJQUVELGlEQUFpRDtJQUNqRCxLQUFLLENBQUMsWUFBWSxDQUFDLEtBQVk7UUFDM0IsTUFBTSxLQUFLLEdBQUcsS0FBSyxDQUFDLE9BQU8sRUFBRSxDQUFDO1FBRTlCLGlGQUFpRjtRQUNqRixNQUFNLFNBQVMsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUM3QyxPQUFPLEtBQUssQ0FBQyxTQUFTLENBQUMsSUFBSSxVQUFVLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQztJQUN0RCxDQUFDO0lBRUQseUJBQXlCO0lBQ3pCLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFhLEVBQUUsTUFBYTtRQUMvQyxPQUFPLE9BQU8sQ0FBQyxHQUFHLENBQUM7WUFDZixJQUFJLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQztZQUN6QixJQUFJLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQztTQUM1QixDQUFDLENBQUM7SUFDUCxDQUFDO0NBQ0o7QUFFRCwyQ0FBMkM7QUFDM0MsTUFBTSxPQUFPLEdBQUc7SUFHWixZQUFZLEdBQVU7UUFDbEIsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUNsQyxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxLQUFLLENBQUMsUUFBUSxDQUFDLEtBQVk7UUFDdkIsZUFBZTtRQUNmLElBQUksTUFBTSxHQUFHLEtBQUssQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUNoQyxJQUFJLE1BQU0sR0FBRyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUM7UUFFakMsc0JBQXNCO1FBQ3RCLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFFdEUsaUJBQWlCO1FBQ2pCLE1BQU0sV0FBVyxHQUFHLEtBQUssQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUN2QyxNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUNqQyxNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUNqQyxNQUFNLEdBQUcsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBRTdCLGVBQWU7UUFDZixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsR0FBRyxFQUFFLENBQUM7UUFDMUIsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDO1FBRTFCLHVCQUF1QjtRQUN2QixNQUFNLE9BQU8sR0FBRyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUM7UUFDcEMsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBRXBDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLElBQUksRUFBRSxJQUFJLENBQUMsQ0FBQztJQUMxQyxDQUFDO0NBQ0oiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIEFFUy0xMjggZW5jcnlwdGlvbiB3cmFwcGVyIHdpdGggYnJvd3NlciBhbmQgTm9kZS5qcyBzdXBwb3J0XG4gKiBcbiAqIFByb3ZpZGVzIEFFUy0xMjggZW5jcnlwdGlvbiBmb3IgdGhlIERQRiBQUkcgY29uc3RydWN0aW9uLlxuICogVXNlcyBhZXMtanMgZm9yIEFFUy1FQ0IgKHdvcmtzIGluIGFsbCBlbnZpcm9ubWVudHMgaW5jbHVkaW5nIFNhZmFyaSkuXG4gKi9cblxuaW1wb3J0IGFlc2pzIGZyb20gJ2Flcy1qcyc7XG5pbXBvcnQgeyBCbG9jayB9IGZyb20gJy4vYmxvY2suanMnO1xuXG4vKiogQUVTLTEyOCBrZXkgd3JhcHBlciB3aXRoIGFzeW5jIGVuY3J5cHRpb24gKi9cbmV4cG9ydCBjbGFzcyBBZXNLZXkge1xuICAgIHByaXZhdGUga2V5Qnl0ZXM6IFVpbnQ4QXJyYXk7XG4gICAgcHJpdmF0ZSBhZXNFY2I6IEluc3RhbmNlVHlwZTx0eXBlb2YgYWVzanMuTW9kZU9mT3BlcmF0aW9uLmVjYj47XG5cbiAgICBjb25zdHJ1Y3RvcihrZXlCbG9jazogQmxvY2spIHtcbiAgICAgICAgLy8gQ3JlYXRlIGEgMTI4LWJpdCBrZXkgZnJvbSB0aGUgYmxvY2tcbiAgICAgICAgdGhpcy5rZXlCeXRlcyA9IGtleUJsb2NrLnRvQnl0ZXMoKTtcbiAgICAgICAgLy8gSW5pdGlhbGl6ZSBBRVMtRUNCIG1vZGUgdXNpbmcgYWVzLWpzICh3b3JrcyBpbiBhbGwgZW52aXJvbm1lbnRzKVxuICAgICAgICB0aGlzLmFlc0VjYiA9IG5ldyBhZXNqcy5Nb2RlT2ZPcGVyYXRpb24uZWNiKHRoaXMua2V5Qnl0ZXMpO1xuICAgIH1cblxuICAgIC8qKiBFbmNyeXB0IGEgc2luZ2xlIGJsb2NrIChyZXR1cm5zIG5ldyBibG9jaykgKi9cbiAgICBhc3luYyBlbmNyeXB0QmxvY2soYmxvY2s6IEJsb2NrKTogUHJvbWlzZTxCbG9jaz4ge1xuICAgICAgICBjb25zdCBieXRlcyA9IGJsb2NrLnRvQnl0ZXMoKTtcbiAgICAgICAgXG4gICAgICAgIC8vIFVzZSBhZXMtanMgZm9yIEFFUy1FQ0IgZW5jcnlwdGlvbiAod29ya3MgaW4gYWxsIGVudmlyb25tZW50cyBpbmNsdWRpbmcgU2FmYXJpKVxuICAgICAgICBjb25zdCBlbmNyeXB0ZWQgPSB0aGlzLmFlc0VjYi5lbmNyeXB0KGJ5dGVzKTtcbiAgICAgICAgcmV0dXJuIEJsb2NrLmZyb21CeXRlcyhuZXcgVWludDhBcnJheShlbmNyeXB0ZWQpKTtcbiAgICB9XG5cbiAgICAvKiogRW5jcnlwdCB0d28gYmxvY2tzICovXG4gICAgYXN5bmMgZW5jcnlwdFR3b0Jsb2NrcyhibG9jazA6IEJsb2NrLCBibG9jazE6IEJsb2NrKTogUHJvbWlzZTxbQmxvY2ssIEJsb2NrXT4ge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5hbGwoW1xuICAgICAgICAgICAgdGhpcy5lbmNyeXB0QmxvY2soYmxvY2swKSxcbiAgICAgICAgICAgIHRoaXMuZW5jcnlwdEJsb2NrKGJsb2NrMSlcbiAgICAgICAgXSk7XG4gICAgfVxufVxuXG4vKiogUFJHIChQc2V1ZG9yYW5kb20gR2VuZXJhdG9yKSBmb3IgRFBGICovXG5leHBvcnQgY2xhc3MgUHJnIHtcbiAgICBwcml2YXRlIGFlc0tleTogQWVzS2V5O1xuXG4gICAgY29uc3RydWN0b3Ioa2V5OiBCbG9jaykge1xuICAgICAgICB0aGlzLmFlc0tleSA9IG5ldyBBZXNLZXkoa2V5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHZW5lcmF0ZSBwc2V1ZG9yYW5kb20gb3V0cHV0cyBmcm9tIGEgc2VlZCBibG9ja1xuICAgICAqIFxuICAgICAqIEBwYXJhbSBpbnB1dCAtIFRoZSBzZWVkIGJsb2NrIChMU0Igd2lsbCBiZSB6ZXJvZWQgYmVmb3JlIHVzZSlcbiAgICAgKiBAcmV0dXJucyBbb3V0cHV0MSwgb3V0cHV0MiwgYml0MSwgYml0Ml0gLSBUd28gb3V0cHV0IGJsb2NrcyBhbmQgdHdvIGNvbnRyb2wgYml0c1xuICAgICAqL1xuICAgIGFzeW5jIGdlbmVyYXRlKGlucHV0OiBCbG9jayk6IFByb21pc2U8W0Jsb2NrLCBCbG9jaywgbnVtYmVyLCBudW1iZXJdPiB7XG4gICAgICAgIC8vIFplcm8gdGhlIExTQlxuICAgICAgICBsZXQgc3Rhc2gwID0gaW5wdXQuc2V0THNiWmVybygpO1xuICAgICAgICBsZXQgc3Rhc2gxID0gc3Rhc2gwLnJldmVyc2VMc2IoKTtcblxuICAgICAgICAvLyBFbmNyeXB0IGJvdGggYmxvY2tzXG4gICAgICAgIFtzdGFzaDAsIHN0YXNoMV0gPSBhd2FpdCB0aGlzLmFlc0tleS5lbmNyeXB0VHdvQmxvY2tzKHN0YXNoMCwgc3Rhc2gxKTtcblxuICAgICAgICAvLyBYT1Igd2l0aCBpbnB1dFxuICAgICAgICBjb25zdCBpbnB1dFplcm9lZCA9IGlucHV0LnNldExzYlplcm8oKTtcbiAgICAgICAgc3Rhc2gwID0gc3Rhc2gwLnhvcihpbnB1dFplcm9lZCk7XG4gICAgICAgIHN0YXNoMSA9IHN0YXNoMS54b3IoaW5wdXRaZXJvZWQpO1xuICAgICAgICBzdGFzaDEgPSBzdGFzaDEucmV2ZXJzZUxzYigpO1xuXG4gICAgICAgIC8vIEV4dHJhY3QgYml0c1xuICAgICAgICBjb25zdCBiaXQxID0gc3Rhc2gwLmxzYigpO1xuICAgICAgICBjb25zdCBiaXQyID0gc3Rhc2gxLmxzYigpO1xuXG4gICAgICAgIC8vIFplcm8gTFNCcyBpbiBvdXRwdXRzXG4gICAgICAgIGNvbnN0IG91dHB1dDEgPSBzdGFzaDAuc2V0THNiWmVybygpO1xuICAgICAgICBjb25zdCBvdXRwdXQyID0gc3Rhc2gxLnNldExzYlplcm8oKTtcblxuICAgICAgICByZXR1cm4gW291dHB1dDEsIG91dHB1dDIsIGJpdDEsIGJpdDJdO1xuICAgIH1cbn0iXX0=