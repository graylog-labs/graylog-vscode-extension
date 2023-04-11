'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = void 0;
const vscode = require("vscode");
const graylog_1 = require("./graylog");
const fileSystemProvider_1 = require("./fileSystemProvider");
const utils_1 = require("./utils");
const colorData = require('../themes/color');
function activate(context) {
    (0, utils_1.addColorSettings)(colorData);
    const Graylog = new fileSystemProvider_1.GraylogFileSystemProvider();
    vscode.window.registerTreeDataProvider('graylog', Graylog);
    const connectpart = new graylog_1.ConnectionPart(Graylog, context.secrets);
    context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
    // context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
    // 	connectpart.clearworkspace();
    // }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.RereshWorkSpace', async () => {
        connectpart.refreshWorkspace();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.settingApiInfo', async () => {
        await connectpart.initSettings();
        connectpart.openSettings();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('graylog.selectInstances', async () => {
        await connectpart.initSettings();
        const items = [];
        if (connectpart.apis.apiInfoList && connectpart.apis.apiInfoList.length > 0) {
            for (let i = 0; i < connectpart.apis.apiInfoList.length; i++) {
                items.push({
                    label: connectpart.apis.apiInfoList[i]['apiHostUrl'],
                    index: i
                });
            }
            const result = await vscode.window.showQuickPick(items, {
                canPickMany: true,
                placeHolder: 'Select Servers',
            });
            if (result) {
                connectpart.clearworkspace(result);
            }
        }
    }));
    prepareForWork(connectpart, context.secrets);
    vscode.workspace.onDidChangeTextDocument((e) => {
        // e?.document.save().then((result)=>{
        // 	if(result){
        connectpart.onDidChange(e?.document);
        // }
        // })
    });
    vscode.window.onDidChangeActiveTextEditor(e => {
        if (e?.document)
            // e?.document.save().then((result)=>{
            // if(result){
            connectpart.onDidChange(e?.document);
        // }
        // })
    });
    vscode.workspace.onDidCreateFiles((e) => {
        e.files.map((file) => {
            let name = file.path.replace("/", "").split('.')[0];
            let extension = file.path.replace("/", "").split('.')[1];
            if (file.scheme == 'graylog' && extension == 'grule') {
                connectpart.createRule(name);
            }
        });
    });
}
exports.activate = activate;
async function prepareForWork(connectpart, secretStorage) {
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 && vscode.workspace.workspaceFolders[0].uri.toString().includes("graylog")) {
        await connectpart.initSettings();
        connectpart.prepareForwork();
    }
    // if(await secretStorage.get("reloaded") == "yes"){
    // 	connectpart.LoginInitialize();
    // }
}
//# sourceMappingURL=extension.js.map