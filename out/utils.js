"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.basename = exports.svgToUri = exports.replaceLinebreaks = exports.truncateString = void 0;
const vscode_1 = require("vscode");
/**
 * Cut off string if it's longer than provided number of characters.
 */
function truncateString(str, max) {
    const chars = [...str];
    return chars.length > max ? `${chars.slice(0, max).join('')}…` : str;
}
exports.truncateString = truncateString;
/**
 * Replace linebreaks with the one whitespace symbol.
 */
function replaceLinebreaks(str, replaceSymbol) {
    return str.replace(/[\n\r\t]+/g, replaceSymbol);
}
exports.replaceLinebreaks = replaceLinebreaks;
/**
 * Transform string svg to {@link Uri}
 */
function svgToUri(svg) {
    return vscode_1.Uri.parse(`data:image/svg+xml;utf8,${svg}`);
}
exports.svgToUri = svgToUri;
/**
 * To work on the web - use this instead of `path.basename`.
 */
function basename(filePath) {
    return filePath.split(/[\\/]/).pop() || '';
}
exports.basename = basename;
//# sourceMappingURL=utils.js.map