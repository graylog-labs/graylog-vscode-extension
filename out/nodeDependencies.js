"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Item = exports.DepNodeProvider = void 0;
const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
class DepNodeProvider {
    constructor(workspaceRoot) {
        this.workspaceRoot = workspaceRoot;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (!this.workspaceRoot) {
            vscode.window.showInformationMessage('No Item in empty workspace');
            return Promise.resolve([]);
        }
        if (element) {
            return Promise.resolve(this.getDepsInPackageJson(element.pathStr));
        }
        else {
            if (this.pathExists(this.workspaceRoot)) {
                return Promise.resolve(this.getDepsInPackageJson(this.workspaceRoot));
            }
            else {
                vscode.window.showInformationMessage('Workspace has no package.json');
                return Promise.resolve([]);
            }
        }
    }
    /**
     * Given the path to package.json, read all its dependencies and devDependencies.
     */
    getDepsInPackageJson(pathStr) {
        const workspaceRoot = this.workspaceRoot;
        if (this.pathExists(pathStr) && workspaceRoot) {
            const toDep = (moduleName) => {
                if (fs.lstatSync(path.join(pathStr, moduleName)).isDirectory()) {
                    return new Item(path.join(pathStr, moduleName), moduleName, vscode.TreeItemCollapsibleState.Collapsed);
                }
                else {
                    return new Item(path.join(pathStr, moduleName), moduleName, vscode.TreeItemCollapsibleState.None, {
                        command: "nodeDependencies.openDocument",
                        title: 'openDocument',
                        arguments: [path.join(pathStr, moduleName)]
                    });
                }
            };
            const items = fs.readdirSync(pathStr).map(str => toDep(str));
            return items;
        }
        else {
            return [];
        }
    }
    pathExists(p) {
        try {
            fs.accessSync(p);
        }
        catch (err) {
            return false;
        }
        return true;
    }
}
exports.DepNodeProvider = DepNodeProvider;
class Item extends vscode.TreeItem {
    constructor(pathStr, label, collapsibleState, command) {
        super(label, collapsibleState);
        this.pathStr = pathStr;
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.command = command;
        this.iconPath = {
            light: path.join(__filename, '..', '..', 'resources', 'light', 'dependency.svg'),
            dark: path.join(__filename, '..', '..', 'resources', 'dark', 'dependency.svg')
        };
        this.contextValue = 'dependency';
        this.tooltip = `${this.label}`;
    }
}
exports.Item = Item;
//# sourceMappingURL=nodeDependencies.js.map