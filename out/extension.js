'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = void 0;
const vscode = require("vscode");
const nodeDependencies_1 = require("./nodeDependencies");
/*
import { JsonOutlineProvider } from './jsonOutline';
import { FtpExplorer } from './ftpExplorer';
import { FileExplorer } from './fileExplorer';
import { TestViewDragAndDrop } from './testViewDragAndDrop';
import { TestView } from './testView';
*/
function activate(context) {
    const rootPath = (vscode.workspace.workspaceFolders && (vscode.workspace.workspaceFolders.length > 0))
        ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined;
    // Samples of `window.registerTreeDataProvider`
    const nodeDependenciesProvider = new nodeDependencies_1.DepNodeProvider(rootPath);
    vscode.window.registerTreeDataProvider('nodeDependencies', nodeDependenciesProvider);
    vscode.commands.registerCommand('nodeDependencies.openDocument', (openpath) => {
        vscode.workspace.openTextDocument(openpath).then(doc => {
            vscode.window.showTextDocument(doc);
        });
    });
    vscode.commands.registerCommand('nodeDependencies.refreshEntry', () => nodeDependenciesProvider.refresh());
    /*
    vscode.commands.registerCommand('extension.openPackageOnNpm', moduleName => vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(`https://www.npmjs.com/package/${moduleName}`)));
    vscode.commands.registerCommand('nodeDependencies.addEntry', () => vscode.window.showInformationMessage(`Successfully called add entry.`));
    vscode.commands.registerCommand('nodeDependencies.editEntry', (node: Dependency) => vscode.window.showInformationMessage(`Successfully called edit entry on ${node.label}.`));
    vscode.commands.registerCommand('nodeDependencies.deleteEntry', (node: Dependency) => vscode.window.showInformationMessage(`Successfully called delete entry on ${node.label}.`));

    const jsonOutlineProvider = new JsonOutlineProvider(context);
    vscode.window.registerTreeDataProvider('jsonOutline', jsonOutlineProvider);
    vscode.commands.registerCommand('jsonOutline.refresh', () => jsonOutlineProvider.refresh());
    vscode.commands.registerCommand('jsonOutline.refreshNode', offset => jsonOutlineProvider.refresh(offset));
    vscode.commands.registerCommand('jsonOutline.renameNode', args => {
        let offset = undefined;
        if (args.selectedTreeItems && args.selectedTreeItems.length) {
            offset = args.selectedTreeItems[0];
        } else if (typeof args === 'number') {
            offset = args;
        }
        if (offset) {
            jsonOutlineProvider.rename(offset);
        }
    });
    vscode.commands.registerCommand('extension.openJsonSelection', range => jsonOutlineProvider.select(range));

    // Samples of `window.createView`
    new FtpExplorer(context);
    new FileExplorer(context);

    // Test View
    new TestView(context);

    new TestViewDragAndDrop(context);*/
}
exports.activate = activate;
//# sourceMappingURL=extension.js.map