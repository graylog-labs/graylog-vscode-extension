'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = void 0;
const vscode = require("vscode");
const connectionpart_1 = require("./connectionpart");
const fileSystemProvider_1 = require("./fileSystemProvider");
const colorData = require('../themes/color');
function activate(context) {
    const Graylog = new fileSystemProvider_1.GraylogFileSystemProvider();
    const connectpart = new connectionpart_1.ConnectionPart(Graylog, context.secrets);
    context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
    let initialized = false;
    context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
        await connectpart.LoginInitialize();
    }));
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 && vscode.workspace.workspaceFolders[0].name == 'Graylog API') {
        connectpart.prepareForwork();
    }
    vscode.workspace.onDidChangeTextDocument((e) => {
        if (connectpart.accountUserName != "")
            connectpart.onDidChange(e.document);
    });
}
exports.activate = activate;
//# sourceMappingURL=extension.js.map