import * as vscode from 'vscode';
import { ConnectionPart } from './graylog';
/**
 * CodelensProvider
 */
export class CodelensProvider implements vscode.CodeLensProvider {

	private codeLenses: vscode.CodeLens[] = [];

	private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
	public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

	constructor(private connectpart:ConnectionPart) {
	}

	public provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] | Thenable<vscode.CodeLens[]> {		
        this.codeLenses = [];
        this.connectpart.errors.map((error)=>{
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

    
	public resolveCodeLens(codeLens: vscode.CodeLens, token: vscode.CancellationToken) {
        codeLens.command = {
            title: "Codelens provided by sample extension",
            tooltip: "Tooltip provided by sample extension",
            command: "",
            arguments: ["Argument 1", false]
        };

        return codeLens;
	}
}

