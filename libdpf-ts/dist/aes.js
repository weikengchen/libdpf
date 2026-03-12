"use strict";
/**
 * AES-128 encryption wrapper using Node.js crypto module
 *
 * Provides AES-128 encryption for the DPF PRG construction.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Prg = exports.AesKey = void 0;
const crypto = __importStar(require("crypto"));
const block_1 = require("./block");
/** AES-128 key wrapper */
class AesKey {
    constructor(keyBlock) {
        // Create a 128-bit key from the block
        this.key = Buffer.from(keyBlock.toBytes());
    }
    /** Encrypt a single block in-place (returns new block) */
    encryptBlock(block) {
        const bytes = block.toBytes();
        // Use AES-128-ECB (no IV needed for single block encryption)
        const cipher = crypto.createCipheriv('aes-128-ecb', this.key, null);
        cipher.setAutoPadding(false);
        const encrypted = Buffer.concat([
            cipher.update(Buffer.from(bytes)),
            cipher.final()
        ]);
        return block_1.Block.fromBytes(new Uint8Array(encrypted));
    }
    /** Encrypt two blocks */
    encryptTwoBlocks(block0, block1) {
        return [this.encryptBlock(block0), this.encryptBlock(block1)];
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
    generate(input) {
        // Zero the LSB
        let stash0 = input.setLsbZero();
        let stash1 = stash0.reverseLsb();
        // Encrypt both blocks
        [stash0, stash1] = this.aesKey.encryptTwoBlocks(stash0, stash1);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWVzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2Flcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUE7Ozs7R0FJRzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBRUgsK0NBQWlDO0FBQ2pDLG1DQUFnQztBQUVoQywwQkFBMEI7QUFDMUIsTUFBYSxNQUFNO0lBR2YsWUFBWSxRQUFlO1FBQ3ZCLHNDQUFzQztRQUN0QyxJQUFJLENBQUMsR0FBRyxHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sRUFBRSxDQUFDLENBQUM7SUFDL0MsQ0FBQztJQUVELDBEQUEwRDtJQUMxRCxZQUFZLENBQUMsS0FBWTtRQUNyQixNQUFNLEtBQUssR0FBRyxLQUFLLENBQUMsT0FBTyxFQUFFLENBQUM7UUFFOUIsNkRBQTZEO1FBQzdELE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxjQUFjLENBQUMsYUFBYSxFQUFFLElBQUksQ0FBQyxHQUFHLEVBQUUsSUFBSSxDQUFDLENBQUM7UUFDcEUsTUFBTSxDQUFDLGNBQWMsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUU3QixNQUFNLFNBQVMsR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDO1lBQzVCLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUNqQyxNQUFNLENBQUMsS0FBSyxFQUFFO1NBQ2pCLENBQUMsQ0FBQztRQUVILE9BQU8sYUFBSyxDQUFDLFNBQVMsQ0FBQyxJQUFJLFVBQVUsQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDO0lBQ3RELENBQUM7SUFFRCx5QkFBeUI7SUFDekIsZ0JBQWdCLENBQUMsTUFBYSxFQUFFLE1BQWE7UUFDekMsT0FBTyxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLEVBQUUsSUFBSSxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO0lBQ2xFLENBQUM7Q0FDSjtBQTVCRCx3QkE0QkM7QUFFRCwyQ0FBMkM7QUFDM0MsTUFBYSxHQUFHO0lBR1osWUFBWSxHQUFVO1FBQ2xCLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDbEMsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0gsUUFBUSxDQUFDLEtBQVk7UUFDakIsZUFBZTtRQUNmLElBQUksTUFBTSxHQUFHLEtBQUssQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUNoQyxJQUFJLE1BQU0sR0FBRyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUM7UUFFakMsc0JBQXNCO1FBQ3RCLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsZ0JBQWdCLENBQUMsTUFBTSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBRWhFLGlCQUFpQjtRQUNqQixNQUFNLFdBQVcsR0FBRyxLQUFLLENBQUMsVUFBVSxFQUFFLENBQUM7UUFDdkMsTUFBTSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsV0FBVyxDQUFDLENBQUM7UUFDakMsTUFBTSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsV0FBVyxDQUFDLENBQUM7UUFDakMsTUFBTSxHQUFHLE1BQU0sQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUU3QixlQUFlO1FBQ2YsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDO1FBQzFCLE1BQU0sSUFBSSxHQUFHLE1BQU0sQ0FBQyxHQUFHLEVBQUUsQ0FBQztRQUUxQix1QkFBdUI7UUFDdkIsTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBQ3BDLE1BQU0sT0FBTyxHQUFHLE1BQU0sQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUVwQyxPQUFPLENBQUMsT0FBTyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7SUFDMUMsQ0FBQztDQUNKO0FBckNELGtCQXFDQyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogQUVTLTEyOCBlbmNyeXB0aW9uIHdyYXBwZXIgdXNpbmcgTm9kZS5qcyBjcnlwdG8gbW9kdWxlXG4gKiBcbiAqIFByb3ZpZGVzIEFFUy0xMjggZW5jcnlwdGlvbiBmb3IgdGhlIERQRiBQUkcgY29uc3RydWN0aW9uLlxuICovXG5cbmltcG9ydCAqIGFzIGNyeXB0byBmcm9tICdjcnlwdG8nO1xuaW1wb3J0IHsgQmxvY2sgfSBmcm9tICcuL2Jsb2NrJztcblxuLyoqIEFFUy0xMjgga2V5IHdyYXBwZXIgKi9cbmV4cG9ydCBjbGFzcyBBZXNLZXkge1xuICAgIHByaXZhdGUga2V5OiBCdWZmZXI7XG5cbiAgICBjb25zdHJ1Y3RvcihrZXlCbG9jazogQmxvY2spIHtcbiAgICAgICAgLy8gQ3JlYXRlIGEgMTI4LWJpdCBrZXkgZnJvbSB0aGUgYmxvY2tcbiAgICAgICAgdGhpcy5rZXkgPSBCdWZmZXIuZnJvbShrZXlCbG9jay50b0J5dGVzKCkpO1xuICAgIH1cblxuICAgIC8qKiBFbmNyeXB0IGEgc2luZ2xlIGJsb2NrIGluLXBsYWNlIChyZXR1cm5zIG5ldyBibG9jaykgKi9cbiAgICBlbmNyeXB0QmxvY2soYmxvY2s6IEJsb2NrKTogQmxvY2sge1xuICAgICAgICBjb25zdCBieXRlcyA9IGJsb2NrLnRvQnl0ZXMoKTtcbiAgICAgICAgXG4gICAgICAgIC8vIFVzZSBBRVMtMTI4LUVDQiAobm8gSVYgbmVlZGVkIGZvciBzaW5nbGUgYmxvY2sgZW5jcnlwdGlvbilcbiAgICAgICAgY29uc3QgY2lwaGVyID0gY3J5cHRvLmNyZWF0ZUNpcGhlcml2KCdhZXMtMTI4LWVjYicsIHRoaXMua2V5LCBudWxsKTtcbiAgICAgICAgY2lwaGVyLnNldEF1dG9QYWRkaW5nKGZhbHNlKTtcbiAgICAgICAgXG4gICAgICAgIGNvbnN0IGVuY3J5cHRlZCA9IEJ1ZmZlci5jb25jYXQoW1xuICAgICAgICAgICAgY2lwaGVyLnVwZGF0ZShCdWZmZXIuZnJvbShieXRlcykpLFxuICAgICAgICAgICAgY2lwaGVyLmZpbmFsKClcbiAgICAgICAgXSk7XG4gICAgICAgIFxuICAgICAgICByZXR1cm4gQmxvY2suZnJvbUJ5dGVzKG5ldyBVaW50OEFycmF5KGVuY3J5cHRlZCkpO1xuICAgIH1cblxuICAgIC8qKiBFbmNyeXB0IHR3byBibG9ja3MgKi9cbiAgICBlbmNyeXB0VHdvQmxvY2tzKGJsb2NrMDogQmxvY2ssIGJsb2NrMTogQmxvY2spOiBbQmxvY2ssIEJsb2NrXSB7XG4gICAgICAgIHJldHVybiBbdGhpcy5lbmNyeXB0QmxvY2soYmxvY2swKSwgdGhpcy5lbmNyeXB0QmxvY2soYmxvY2sxKV07XG4gICAgfVxufVxuXG4vKiogUFJHIChQc2V1ZG9yYW5kb20gR2VuZXJhdG9yKSBmb3IgRFBGICovXG5leHBvcnQgY2xhc3MgUHJnIHtcbiAgICBwcml2YXRlIGFlc0tleTogQWVzS2V5O1xuXG4gICAgY29uc3RydWN0b3Ioa2V5OiBCbG9jaykge1xuICAgICAgICB0aGlzLmFlc0tleSA9IG5ldyBBZXNLZXkoa2V5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHZW5lcmF0ZSBwc2V1ZG9yYW5kb20gb3V0cHV0cyBmcm9tIGEgc2VlZCBibG9ja1xuICAgICAqIFxuICAgICAqIEBwYXJhbSBpbnB1dCAtIFRoZSBzZWVkIGJsb2NrIChMU0Igd2lsbCBiZSB6ZXJvZWQgYmVmb3JlIHVzZSlcbiAgICAgKiBAcmV0dXJucyBbb3V0cHV0MSwgb3V0cHV0MiwgYml0MSwgYml0Ml0gLSBUd28gb3V0cHV0IGJsb2NrcyBhbmQgdHdvIGNvbnRyb2wgYml0c1xuICAgICAqL1xuICAgIGdlbmVyYXRlKGlucHV0OiBCbG9jayk6IFtCbG9jaywgQmxvY2ssIG51bWJlciwgbnVtYmVyXSB7XG4gICAgICAgIC8vIFplcm8gdGhlIExTQlxuICAgICAgICBsZXQgc3Rhc2gwID0gaW5wdXQuc2V0THNiWmVybygpO1xuICAgICAgICBsZXQgc3Rhc2gxID0gc3Rhc2gwLnJldmVyc2VMc2IoKTtcblxuICAgICAgICAvLyBFbmNyeXB0IGJvdGggYmxvY2tzXG4gICAgICAgIFtzdGFzaDAsIHN0YXNoMV0gPSB0aGlzLmFlc0tleS5lbmNyeXB0VHdvQmxvY2tzKHN0YXNoMCwgc3Rhc2gxKTtcblxuICAgICAgICAvLyBYT1Igd2l0aCBpbnB1dFxuICAgICAgICBjb25zdCBpbnB1dFplcm9lZCA9IGlucHV0LnNldExzYlplcm8oKTtcbiAgICAgICAgc3Rhc2gwID0gc3Rhc2gwLnhvcihpbnB1dFplcm9lZCk7XG4gICAgICAgIHN0YXNoMSA9IHN0YXNoMS54b3IoaW5wdXRaZXJvZWQpO1xuICAgICAgICBzdGFzaDEgPSBzdGFzaDEucmV2ZXJzZUxzYigpO1xuXG4gICAgICAgIC8vIEV4dHJhY3QgYml0c1xuICAgICAgICBjb25zdCBiaXQxID0gc3Rhc2gwLmxzYigpO1xuICAgICAgICBjb25zdCBiaXQyID0gc3Rhc2gxLmxzYigpO1xuXG4gICAgICAgIC8vIFplcm8gTFNCcyBpbiBvdXRwdXRzXG4gICAgICAgIGNvbnN0IG91dHB1dDEgPSBzdGFzaDAuc2V0THNiWmVybygpO1xuICAgICAgICBjb25zdCBvdXRwdXQyID0gc3Rhc2gxLnNldExzYlplcm8oKTtcblxuICAgICAgICByZXR1cm4gW291dHB1dDEsIG91dHB1dDIsIGJpdDEsIGJpdDJdO1xuICAgIH1cbn0iXX0=