"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CodelensProvider = void 0;
const vscode = require("vscode");
/**
 * CodelensProvider
 */
class CodelensProvider {
    constructor(connectpart) {
        this.connectpart = connectpart;
        this.codeLenses = [];
        this._onDidChangeCodeLenses = new vscode.EventEmitter();
        this.onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
    }
    provideCodeLenses(document, token) {
        this.codeLenses = [];
        this.connectpart.errors.forEach((error) => {
            let line = error.line;
            let indexOf = error.position_in_line;
            let position = new vscode.Position(line, indexOf);
            let range = document.getWordRangeAtPosition(position);
            if (range) {
                this.codeLenses.push(new vscode.CodeLens(range));
            }
        });
        return this.codeLenses;
    }
    resolveCodeLens(codeLens, token) {
        codeLens.command = {
            title: "Codelens provided by sample extension",
            tooltip: "Tooltip provided by sample extension",
            command: "",
            arguments: ["Argument 1", false]
        };
        return codeLens;
    }
}
exports.CodelensProvider = CodelensProvider;
//# sourceMappingURL=CodelensProvider.js.map