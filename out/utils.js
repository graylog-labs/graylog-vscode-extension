"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFormatedHashValue = exports.getPathSeparator = exports.addColorSettings = exports.basename = exports.svgToUri = exports.replaceLinebreaks = exports.truncateString = void 0;
const vscode = require("vscode");
const path = require('path');
const ts_md5_1 = require("ts-md5");
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
    return vscode.Uri.parse(`data:image/svg+xml;utf8,${svg}`);
}
exports.svgToUri = svgToUri;
/**
 * To work on the web - use this instead of `path.basename`.
 */
function basename(filePath) {
    return filePath.split(/[\\/]/).pop() || '';
}
exports.basename = basename;
function addColorSettings(colorData) {
    (async () => {
        const config = vscode.workspace.getConfiguration();
        await config.update('editor.tokenColorCustomizations', colorData, vscode.ConfigurationTarget.Global);
    })();
}
exports.addColorSettings = addColorSettings;
function getPathSeparator() {
    return path.sep;
}
exports.getPathSeparator = getPathSeparator;
function getFormatedHashValue(inputString) {
    const hashresult = ts_md5_1.Md5.hashStr(inputString);
    let tempResult = hashresult.split("");
    [23, 18, 13, 8].forEach((index) => {
        tempResult.splice(index, 0, "-");
    });
    return tempResult.join("");
}
exports.getFormatedHashValue = getFormatedHashValue;
//# sourceMappingURL=utils.js.map