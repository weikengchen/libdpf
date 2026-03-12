"use strict";
/**
 * libdpf - Distributed Point Function Library
 *
 * A TypeScript implementation of 2-party 1-bit Distributed Point Function (DPF)
 * from "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_KEY_LOW = exports.DEFAULT_KEY_HIGH = exports.defaultKey = exports.evalFull = exports.evalAt = exports.gen = exports.Dpf = exports.DpfKey = exports.Prg = exports.AesKey = exports.Block = void 0;
var block_1 = require("./block");
Object.defineProperty(exports, "Block", { enumerable: true, get: function () { return block_1.Block; } });
var aes_1 = require("./aes");
Object.defineProperty(exports, "AesKey", { enumerable: true, get: function () { return aes_1.AesKey; } });
Object.defineProperty(exports, "Prg", { enumerable: true, get: function () { return aes_1.Prg; } });
var key_1 = require("./key");
Object.defineProperty(exports, "DpfKey", { enumerable: true, get: function () { return key_1.DpfKey; } });
var dpf_1 = require("./dpf");
Object.defineProperty(exports, "Dpf", { enumerable: true, get: function () { return dpf_1.Dpf; } });
Object.defineProperty(exports, "gen", { enumerable: true, get: function () { return dpf_1.gen; } });
Object.defineProperty(exports, "evalAt", { enumerable: true, get: function () { return dpf_1.evalAt; } });
Object.defineProperty(exports, "evalFull", { enumerable: true, get: function () { return dpf_1.evalFull; } });
Object.defineProperty(exports, "defaultKey", { enumerable: true, get: function () { return dpf_1.defaultKey; } });
Object.defineProperty(exports, "DEFAULT_KEY_HIGH", { enumerable: true, get: function () { return dpf_1.DEFAULT_KEY_HIGH; } });
Object.defineProperty(exports, "DEFAULT_KEY_LOW", { enumerable: true, get: function () { return dpf_1.DEFAULT_KEY_LOW; } });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBOzs7OztHQUtHOzs7QUFFSCxpQ0FBZ0M7QUFBdkIsOEZBQUEsS0FBSyxPQUFBO0FBQ2QsNkJBQW9DO0FBQTNCLDZGQUFBLE1BQU0sT0FBQTtBQUFFLDBGQUFBLEdBQUcsT0FBQTtBQUNwQiw2QkFBK0I7QUFBdEIsNkZBQUEsTUFBTSxPQUFBO0FBQ2YsNkJBQWtHO0FBQXpGLDBGQUFBLEdBQUcsT0FBQTtBQUFFLDBGQUFBLEdBQUcsT0FBQTtBQUFFLDZGQUFBLE1BQU0sT0FBQTtBQUFFLCtGQUFBLFFBQVEsT0FBQTtBQUFFLGlHQUFBLFVBQVUsT0FBQTtBQUFFLHVHQUFBLGdCQUFnQixPQUFBO0FBQUUsc0dBQUEsZUFBZSxPQUFBIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBsaWJkcGYgLSBEaXN0cmlidXRlZCBQb2ludCBGdW5jdGlvbiBMaWJyYXJ5XG4gKiBcbiAqIEEgVHlwZVNjcmlwdCBpbXBsZW1lbnRhdGlvbiBvZiAyLXBhcnR5IDEtYml0IERpc3RyaWJ1dGVkIFBvaW50IEZ1bmN0aW9uIChEUEYpXG4gKiBmcm9tIFwiRnVuY3Rpb24gU2VjcmV0IFNoYXJpbmc6IEltcHJvdmVtZW50cyBhbmQgRXh0ZW5zaW9uc1wiIChCb3lsZSBldCBhbC4sIENDUycxNikuXG4gKi9cblxuZXhwb3J0IHsgQmxvY2sgfSBmcm9tICcuL2Jsb2NrJztcbmV4cG9ydCB7IEFlc0tleSwgUHJnIH0gZnJvbSAnLi9hZXMnO1xuZXhwb3J0IHsgRHBmS2V5IH0gZnJvbSAnLi9rZXknO1xuZXhwb3J0IHsgRHBmLCBnZW4sIGV2YWxBdCwgZXZhbEZ1bGwsIGRlZmF1bHRLZXksIERFRkFVTFRfS0VZX0hJR0gsIERFRkFVTFRfS0VZX0xPVyB9IGZyb20gJy4vZHBmJztcbiJdfQ==