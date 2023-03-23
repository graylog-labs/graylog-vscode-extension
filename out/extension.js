'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = void 0;
const vscode = require("vscode");
const connectionpart_1 = require("./connectionpart");
const fileSystemProvider_1 = require("./fileSystemProvider");
function activate(context) {
    console.log('graylog says "Hello"');
    const Graylog = new fileSystemProvider_1.GraylogFileSystemProvider();
    const connectpart = new connectionpart_1.ConnectionPart(Graylog);
    context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
    let initialized = false;
    context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
        await connectpart.LoginInitialize();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.reset', _ => {
        for (const [name] of Graylog.readDirectory(vscode.Uri.parse('graylog:/'))) {
            Graylog.delete(vscode.Uri.parse(`graylog:/${name}`));
        }
        initialized = false;
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.addFile', _ => {
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
    }));
    context.subscriptions.push((vscode.commands.registerCommand('graylog.deleteFile', _ => {
        if (initialized) {
            Graylog.delete(vscode.Uri.parse('graylog:/file.txt'));
        }
    })));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.init', _ => {
        if (initialized) {
            return;
        }
        initialized = true;
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.html`), Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'), { create: true, overwrite: true });
    }));
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 && vscode.workspace.workspaceFolders[0].name == 'Graylog API') {
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.html`), Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'), { create: true, overwrite: true });
    }
}
exports.activate = activate;
function randomData(lineCnt, lineLen = 155) {
    const lines = [];
    for (let i = 0; i < lineCnt; i++) {
        let line = '';
        while (line.length < lineLen) {
            line += Math.random().toString(2 + (i % 34)).substr(2);
        }
        lines.push(line.substr(0, lineLen));
    }
    return Buffer.from(lines.join('\n'), 'utf8');
}
//# sourceMappingURL=extension.js.map