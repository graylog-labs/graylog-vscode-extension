"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsonOutlineProvider = void 0;
const vscode = require("vscode");
const json = require("jsonc-parser");
const path = require("path");
class JsonOutlineProvider {
    constructor(context) {
        this.context = context;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.text = '';
        this.autoRefresh = true;
        vscode.window.onDidChangeActiveTextEditor(() => this.onActiveEditorChanged());
        vscode.workspace.onDidChangeTextDocument(e => this.onDocumentChanged(e));
        this.autoRefresh = vscode.workspace.getConfiguration('jsonOutline').get('autorefresh', false);
        vscode.workspace.onDidChangeConfiguration(() => {
            this.autoRefresh = vscode.workspace.getConfiguration('jsonOutline').get('autorefresh', false);
        });
        this.onActiveEditorChanged();
    }
    refresh(offset) {
        this.parseTree();
        if (offset) {
            this._onDidChangeTreeData.fire(offset);
        }
        else {
            this._onDidChangeTreeData.fire(undefined);
        }
    }
    rename(offset) {
        vscode.window.showInputBox({ placeHolder: 'Enter the new label' }).then(value => {
            const editor = this.editor;
            const tree = this.tree;
            if (value !== null && value !== undefined && editor && tree) {
                editor.edit(editBuilder => {
                    const path = json.getLocation(this.text, offset).path;
                    let propertyNode = json.findNodeAtLocation(tree, path);
                    if (propertyNode.parent?.type !== 'array') {
                        propertyNode = propertyNode.parent?.children ? propertyNode.parent.children[0] : undefined;
                    }
                    if (propertyNode) {
                        const range = new vscode.Range(editor.document.positionAt(propertyNode.offset), editor.document.positionAt(propertyNode.offset + propertyNode.length));
                        editBuilder.replace(range, `"${value}"`);
                        setTimeout(() => {
                            this.parseTree();
                            this.refresh(offset);
                        }, 100);
                    }
                });
            }
        });
    }
    onActiveEditorChanged() {
        if (vscode.window.activeTextEditor) {
            if (vscode.window.activeTextEditor.document.uri.scheme === 'file') {
                const enabled = vscode.window.activeTextEditor.document.languageId === 'json' || vscode.window.activeTextEditor.document.languageId === 'jsonc';
                vscode.commands.executeCommand('setContext', 'jsonOutlineEnabled', enabled);
                if (enabled) {
                    this.refresh();
                }
            }
        }
        else {
            vscode.commands.executeCommand('setContext', 'jsonOutlineEnabled', false);
        }
    }
    onDocumentChanged(changeEvent) {
        if (this.tree && this.autoRefresh && changeEvent.document.uri.toString() === this.editor?.document.uri.toString()) {
            for (const change of changeEvent.contentChanges) {
                const path = json.getLocation(this.text, this.editor.document.offsetAt(change.range.start)).path;
                path.pop();
                const node = path.length ? json.findNodeAtLocation(this.tree, path) : void 0;
                this.parseTree();
                this._onDidChangeTreeData.fire(node ? node.offset : void 0);
            }
        }
    }
    parseTree() {
        this.text = '';
        this.tree = undefined;
        this.editor = vscode.window.activeTextEditor;
        if (this.editor && this.editor.document) {
            this.text = this.editor.document.getText();
            this.tree = json.parseTree(this.text);
        }
    }
    getChildren(offset) {
        if (offset && this.tree) {
            const path = json.getLocation(this.text, offset).path;
            const node = json.findNodeAtLocation(this.tree, path);
            return Promise.resolve(this.getChildrenOffsets(node));
        }
        else {
            return Promise.resolve(this.tree ? this.getChildrenOffsets(this.tree) : []);
        }
    }
    getChildrenOffsets(node) {
        const offsets = [];
        if (node.children && this.tree) {
            for (const child of node.children) {
                const childPath = json.getLocation(this.text, child.offset).path;
                const childNode = json.findNodeAtLocation(this.tree, childPath);
                if (childNode) {
                    offsets.push(childNode.offset);
                }
            }
        }
        return offsets;
    }
    getTreeItem(offset) {
        if (!this.tree) {
            throw new Error('Invalid tree');
        }
        if (!this.editor) {
            throw new Error('Invalid editor');
        }
        const path = json.getLocation(this.text, offset).path;
        const valueNode = json.findNodeAtLocation(this.tree, path);
        if (valueNode) {
            const hasChildren = valueNode.type === 'object' || valueNode.type === 'array';
            const treeItem = new vscode.TreeItem(this.getLabel(valueNode), hasChildren ? valueNode.type === 'object' ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
            treeItem.command = {
                command: 'extension.openJsonSelection',
                title: '',
                arguments: [new vscode.Range(this.editor.document.positionAt(valueNode.offset), this.editor.document.positionAt(valueNode.offset + valueNode.length))]
            };
            treeItem.iconPath = this.getIcon(valueNode);
            treeItem.contextValue = valueNode.type;
            return treeItem;
        }
        throw (new Error(`Could not find json node at ${path}`));
    }
    select(range) {
        if (this.editor) {
            this.editor.selection = new vscode.Selection(range.start, range.end);
        }
    }
    getIcon(node) {
        const nodeType = node.type;
        if (nodeType === 'boolean') {
            return {
                light: this.context.asAbsolutePath(path.join('resources', 'light', 'boolean.svg')),
                dark: this.context.asAbsolutePath(path.join('resources', 'dark', 'boolean.svg'))
            };
        }
        if (nodeType === 'string') {
            return {
                light: this.context.asAbsolutePath(path.join('resources', 'light', 'string.svg')),
                dark: this.context.asAbsolutePath(path.join('resources', 'dark', 'string.svg'))
            };
        }
        if (nodeType === 'number') {
            return {
                light: this.context.asAbsolutePath(path.join('resources', 'light', 'number.svg')),
                dark: this.context.asAbsolutePath(path.join('resources', 'dark', 'number.svg'))
            };
        }
        return null;
    }
    getLabel(node) {
        if (node.parent?.type === 'array') {
            const prefix = node.parent.children?.indexOf(node).toString();
            if (node.type === 'object') {
                return prefix + ':{ }';
            }
            if (node.type === 'array') {
                return prefix + ':[ ]';
            }
            return prefix + ':' + node.value.toString();
        }
        else {
            const property = node.parent?.children ? node.parent.children[0].value.toString() : '';
            if (node.type === 'array' || node.type === 'object') {
                if (node.type === 'object') {
                    return '{ } ' + property;
                }
                if (node.type === 'array') {
                    return '[ ] ' + property;
                }
            }
            const value = this.editor?.document.getText(new vscode.Range(this.editor.document.positionAt(node.offset), this.editor.document.positionAt(node.offset + node.length)));
            return `${property}: ${value}`;
        }
    }
}
exports.JsonOutlineProvider = JsonOutlineProvider;
//# sourceMappingURL=jsonOutline.js.map