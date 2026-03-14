"use strict";
/**
 * AES-128 encryption wrapper with browser and Node.js support
 *
 * Provides AES-128 encryption for the DPF PRG construction.
 * Uses aes-js for AES-ECB (works in all environments including Safari).
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Prg = exports.AesKey = void 0;
const aes_js_1 = __importDefault(require("aes-js"));
const block_1 = require("./block");
/** AES-128 key wrapper with async encryption */
class AesKey {
    constructor(keyBlock) {
        // Create a 128-bit key from the block
        this.keyBytes = keyBlock.toBytes();
        // Initialize AES-ECB mode using aes-js (works in all environments)
        this.aesEcb = new aes_js_1.default.ModeOfOperation.ecb(this.keyBytes);
    }
    /** Encrypt a single block (returns new block) */
    async encryptBlock(block) {
        const bytes = block.toBytes();
        // Use aes-js for AES-ECB encryption (works in all environments including Safari)
        const encrypted = this.aesEcb.encrypt(bytes);
        return block_1.Block.fromBytes(new Uint8Array(encrypted));
    }
    /** Encrypt two blocks */
    async encryptTwoBlocks(block0, block1) {
        return Promise.all([
            this.encryptBlock(block0),
            this.encryptBlock(block1)
        ]);
    }
}
exports.AesKey = AesKey;
/** PRG (Pseudorandom Generator) for DPF */
class Prg {
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
exports.Prg = Prg;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWVzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2Flcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUE7Ozs7O0dBS0c7Ozs7OztBQUVILG9EQUEyQjtBQUMzQixtQ0FBZ0M7QUFFaEMsZ0RBQWdEO0FBQ2hELE1BQWEsTUFBTTtJQUlmLFlBQVksUUFBZTtRQUN2QixzQ0FBc0M7UUFDdEMsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUMsT0FBTyxFQUFFLENBQUM7UUFDbkMsbUVBQW1FO1FBQ25FLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxnQkFBSyxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQy9ELENBQUM7SUFFRCxpREFBaUQ7SUFDakQsS0FBSyxDQUFDLFlBQVksQ0FBQyxLQUFZO1FBQzNCLE1BQU0sS0FBSyxHQUFHLEtBQUssQ0FBQyxPQUFPLEVBQUUsQ0FBQztRQUU5QixpRkFBaUY7UUFDakYsTUFBTSxTQUFTLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDN0MsT0FBTyxhQUFLLENBQUMsU0FBUyxDQUFDLElBQUksVUFBVSxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUM7SUFDdEQsQ0FBQztJQUVELHlCQUF5QjtJQUN6QixLQUFLLENBQUMsZ0JBQWdCLENBQUMsTUFBYSxFQUFFLE1BQWE7UUFDL0MsT0FBTyxPQUFPLENBQUMsR0FBRyxDQUFDO1lBQ2YsSUFBSSxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUM7WUFDekIsSUFBSSxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUM7U0FDNUIsQ0FBQyxDQUFDO0lBQ1AsQ0FBQztDQUNKO0FBM0JELHdCQTJCQztBQUVELDJDQUEyQztBQUMzQyxNQUFhLEdBQUc7SUFHWixZQUFZLEdBQVU7UUFDbEIsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUNsQyxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxLQUFLLENBQUMsUUFBUSxDQUFDLEtBQVk7UUFDdkIsZUFBZTtRQUNmLElBQUksTUFBTSxHQUFHLEtBQUssQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUNoQyxJQUFJLE1BQU0sR0FBRyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUM7UUFFakMsc0JBQXNCO1FBQ3RCLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxHQUFHLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFFdEUsaUJBQWlCO1FBQ2pCLE1BQU0sV0FBVyxHQUFHLEtBQUssQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUN2QyxNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUNqQyxNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUNqQyxNQUFNLEdBQUcsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBRTdCLGVBQWU7UUFDZixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsR0FBRyxFQUFFLENBQUM7UUFDMUIsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDO1FBRTFCLHVCQUF1QjtRQUN2QixNQUFNLE9BQU8sR0FBRyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUM7UUFDcEMsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBRXBDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLElBQUksRUFBRSxJQUFJLENBQUMsQ0FBQztJQUMxQyxDQUFDO0NBQ0o7QUFyQ0Qsa0JBcUNDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBBRVMtMTI4IGVuY3J5cHRpb24gd3JhcHBlciB3aXRoIGJyb3dzZXIgYW5kIE5vZGUuanMgc3VwcG9ydFxuICogXG4gKiBQcm92aWRlcyBBRVMtMTI4IGVuY3J5cHRpb24gZm9yIHRoZSBEUEYgUFJHIGNvbnN0cnVjdGlvbi5cbiAqIFVzZXMgYWVzLWpzIGZvciBBRVMtRUNCICh3b3JrcyBpbiBhbGwgZW52aXJvbm1lbnRzIGluY2x1ZGluZyBTYWZhcmkpLlxuICovXG5cbmltcG9ydCBhZXNqcyBmcm9tICdhZXMtanMnO1xuaW1wb3J0IHsgQmxvY2sgfSBmcm9tICcuL2Jsb2NrJztcblxuLyoqIEFFUy0xMjgga2V5IHdyYXBwZXIgd2l0aCBhc3luYyBlbmNyeXB0aW9uICovXG5leHBvcnQgY2xhc3MgQWVzS2V5IHtcbiAgICBwcml2YXRlIGtleUJ5dGVzOiBVaW50OEFycmF5O1xuICAgIHByaXZhdGUgYWVzRWNiOiBJbnN0YW5jZVR5cGU8dHlwZW9mIGFlc2pzLk1vZGVPZk9wZXJhdGlvbi5lY2I+O1xuXG4gICAgY29uc3RydWN0b3Ioa2V5QmxvY2s6IEJsb2NrKSB7XG4gICAgICAgIC8vIENyZWF0ZSBhIDEyOC1iaXQga2V5IGZyb20gdGhlIGJsb2NrXG4gICAgICAgIHRoaXMua2V5Qnl0ZXMgPSBrZXlCbG9jay50b0J5dGVzKCk7XG4gICAgICAgIC8vIEluaXRpYWxpemUgQUVTLUVDQiBtb2RlIHVzaW5nIGFlcy1qcyAod29ya3MgaW4gYWxsIGVudmlyb25tZW50cylcbiAgICAgICAgdGhpcy5hZXNFY2IgPSBuZXcgYWVzanMuTW9kZU9mT3BlcmF0aW9uLmVjYih0aGlzLmtleUJ5dGVzKTtcbiAgICB9XG5cbiAgICAvKiogRW5jcnlwdCBhIHNpbmdsZSBibG9jayAocmV0dXJucyBuZXcgYmxvY2spICovXG4gICAgYXN5bmMgZW5jcnlwdEJsb2NrKGJsb2NrOiBCbG9jayk6IFByb21pc2U8QmxvY2s+IHtcbiAgICAgICAgY29uc3QgYnl0ZXMgPSBibG9jay50b0J5dGVzKCk7XG4gICAgICAgIFxuICAgICAgICAvLyBVc2UgYWVzLWpzIGZvciBBRVMtRUNCIGVuY3J5cHRpb24gKHdvcmtzIGluIGFsbCBlbnZpcm9ubWVudHMgaW5jbHVkaW5nIFNhZmFyaSlcbiAgICAgICAgY29uc3QgZW5jcnlwdGVkID0gdGhpcy5hZXNFY2IuZW5jcnlwdChieXRlcyk7XG4gICAgICAgIHJldHVybiBCbG9jay5mcm9tQnl0ZXMobmV3IFVpbnQ4QXJyYXkoZW5jcnlwdGVkKSk7XG4gICAgfVxuXG4gICAgLyoqIEVuY3J5cHQgdHdvIGJsb2NrcyAqL1xuICAgIGFzeW5jIGVuY3J5cHRUd29CbG9ja3MoYmxvY2swOiBCbG9jaywgYmxvY2sxOiBCbG9jayk6IFByb21pc2U8W0Jsb2NrLCBCbG9ja10+IHtcbiAgICAgICAgcmV0dXJuIFByb21pc2UuYWxsKFtcbiAgICAgICAgICAgIHRoaXMuZW5jcnlwdEJsb2NrKGJsb2NrMCksXG4gICAgICAgICAgICB0aGlzLmVuY3J5cHRCbG9jayhibG9jazEpXG4gICAgICAgIF0pO1xuICAgIH1cbn1cblxuLyoqIFBSRyAoUHNldWRvcmFuZG9tIEdlbmVyYXRvcikgZm9yIERQRiAqL1xuZXhwb3J0IGNsYXNzIFByZyB7XG4gICAgcHJpdmF0ZSBhZXNLZXk6IEFlc0tleTtcblxuICAgIGNvbnN0cnVjdG9yKGtleTogQmxvY2spIHtcbiAgICAgICAgdGhpcy5hZXNLZXkgPSBuZXcgQWVzS2V5KGtleSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2VuZXJhdGUgcHNldWRvcmFuZG9tIG91dHB1dHMgZnJvbSBhIHNlZWQgYmxvY2tcbiAgICAgKiBcbiAgICAgKiBAcGFyYW0gaW5wdXQgLSBUaGUgc2VlZCBibG9jayAoTFNCIHdpbGwgYmUgemVyb2VkIGJlZm9yZSB1c2UpXG4gICAgICogQHJldHVybnMgW291dHB1dDEsIG91dHB1dDIsIGJpdDEsIGJpdDJdIC0gVHdvIG91dHB1dCBibG9ja3MgYW5kIHR3byBjb250cm9sIGJpdHNcbiAgICAgKi9cbiAgICBhc3luYyBnZW5lcmF0ZShpbnB1dDogQmxvY2spOiBQcm9taXNlPFtCbG9jaywgQmxvY2ssIG51bWJlciwgbnVtYmVyXT4ge1xuICAgICAgICAvLyBaZXJvIHRoZSBMU0JcbiAgICAgICAgbGV0IHN0YXNoMCA9IGlucHV0LnNldExzYlplcm8oKTtcbiAgICAgICAgbGV0IHN0YXNoMSA9IHN0YXNoMC5yZXZlcnNlTHNiKCk7XG5cbiAgICAgICAgLy8gRW5jcnlwdCBib3RoIGJsb2Nrc1xuICAgICAgICBbc3Rhc2gwLCBzdGFzaDFdID0gYXdhaXQgdGhpcy5hZXNLZXkuZW5jcnlwdFR3b0Jsb2NrcyhzdGFzaDAsIHN0YXNoMSk7XG5cbiAgICAgICAgLy8gWE9SIHdpdGggaW5wdXRcbiAgICAgICAgY29uc3QgaW5wdXRaZXJvZWQgPSBpbnB1dC5zZXRMc2JaZXJvKCk7XG4gICAgICAgIHN0YXNoMCA9IHN0YXNoMC54b3IoaW5wdXRaZXJvZWQpO1xuICAgICAgICBzdGFzaDEgPSBzdGFzaDEueG9yKGlucHV0WmVyb2VkKTtcbiAgICAgICAgc3Rhc2gxID0gc3Rhc2gxLnJldmVyc2VMc2IoKTtcblxuICAgICAgICAvLyBFeHRyYWN0IGJpdHNcbiAgICAgICAgY29uc3QgYml0MSA9IHN0YXNoMC5sc2IoKTtcbiAgICAgICAgY29uc3QgYml0MiA9IHN0YXNoMS5sc2IoKTtcblxuICAgICAgICAvLyBaZXJvIExTQnMgaW4gb3V0cHV0c1xuICAgICAgICBjb25zdCBvdXRwdXQxID0gc3Rhc2gwLnNldExzYlplcm8oKTtcbiAgICAgICAgY29uc3Qgb3V0cHV0MiA9IHN0YXNoMS5zZXRMc2JaZXJvKCk7XG5cbiAgICAgICAgcmV0dXJuIFtvdXRwdXQxLCBvdXRwdXQyLCBiaXQxLCBiaXQyXTtcbiAgICB9XG59Il19