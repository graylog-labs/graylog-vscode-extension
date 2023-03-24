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
    addColorSettings();
    //	const codelensProvider = new CodelensProvider(connectpart);
    //	vscode.languages.registerCodeLensProvider("*",codelensProvider);
    context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
    let initialized = false;
    context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
        await connectpart.LoginInitialize();
    }));
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 && vscode.workspace.workspaceFolders[0].name == 'Graylog API') {
        connectpart.prepareForwork();
    }
    vscode.workspace.onDidChangeTextDocument((e) => {
        if (connectpart.apiUrl != "")
            connectpart.onDidChange(e.document);
    });
}
exports.activate = activate;
function addColorSettings() {
    (async () => {
        const config = vscode.workspace.getConfiguration();
        let tokenColorCustomizations = config.inspect('editor.tokenColorCustomizations')?.globalValue;
        // if (!tokenColorCustomizations) {
        // 	tokenColorCustomizations = {};
        // }
        // if (!Object.hasOwnProperty.call(tokenColorCustomizations, 'textMateRules')) {
        // 	tokenColorCustomizations['textMateRules'] = [];
        // }
        const tokenColor = [];
        const colorDataLength = colorData.length;
        const tokenColorLength = tokenColor.length;
        for (let i = 0; i < colorDataLength; i++) {
            const name = colorData[i].name;
            let exist = false;
            for (let j = 0; j < tokenColorLength; j++) {
                if (tokenColor[j].name === name) {
                    exist = true;
                    break;
                }
            }
            if (!exist) {
                tokenColor.push(colorData[i]);
            }
        }
        await config.update('editor.tokenColorCustomizations', tokenColorCustomizations, vscode.ConfigurationTarget.Global);
    })();
}
//# sourceMappingURL=extension.js.map