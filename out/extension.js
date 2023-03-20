'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = void 0;
const vscode = require("vscode");
const nodeDependencies_1 = require("./nodeDependencies");
const connectionpart_1 = require("./connectionpart");
const fileSystemProvider_1 = require("./fileSystemProvider");
function activate(context) {
    const graylogFilesystem = new fileSystemProvider_1.GraylogFileSystemProvider();
    const connectionpart = new connectionpart_1.ConnectionPart(graylogFilesystem);
    const rootPath = (vscode.workspace.workspaceFolders && (vscode.workspace.workspaceFolders.length > 0))
        ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined;
    vscode.workspace.registerFileSystemProvider('graylog', graylogFilesystem);
    const nodeDependenciesProvider = new nodeDependencies_1.DepNodeProvider(rootPath);
    vscode.window.registerTreeDataProvider('nodeDependencies', nodeDependenciesProvider);
    vscode.commands.registerCommand('nodeDependencies.openDocument', (openpath) => {
        vscode.workspace.openTextDocument(openpath).then(doc => {
            vscode.window.showTextDocument(doc);
        });
    });
    vscode.commands.registerCommand('nodeDependencies.refreshEntry', () => nodeDependenciesProvider.refresh());
}
exports.activate = activate;
//# sourceMappingURL=extension.js.map