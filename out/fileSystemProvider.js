"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.GraylogFileSystemProvider = exports.MyTreeItem = exports.Directory = exports.File = void 0;
const path = require("path");
const vscode = require("vscode");
const interfaces_1 = require("./interfaces");
class File {
    constructor(name) {
        this.type = vscode.FileType.File;
        this.ctime = Date.now();
        this.mtime = Date.now();
        this.size = 0;
        this.name = name;
    }
}
exports.File = File;
class Directory {
    constructor(name) {
        this.type = vscode.FileType.Directory;
        this.ctime = Date.now();
        this.mtime = Date.now();
        this.size = 0;
        this.name = name;
        this.entries = new Map();
    }
}
exports.Directory = Directory;
const vscode_1 = require("vscode");
class MyTreeItem extends vscode.TreeItem {
    constructor(label, checked, pathUri, state, command, iconPath) {
        super(label, vscode_1.TreeItemCollapsibleState.Collapsed);
        this.command = command;
        this.iconPath = iconPath;
        this.collapsibleState = state;
        this.pathUri = pathUri;
        this.command = command;
        this.iconPath = iconPath;
        this.checked = checked;
    }
}
exports.MyTreeItem = MyTreeItem;
class GraylogFileSystemProvider {
    constructor() {
        this.treeViewMode = interfaces_1.TreeViewModes.normalMode;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.workspaceRoot = vscode.Uri.parse('graylog:/');
        this.createEditStatus = interfaces_1.createEditStatus.normal;
        this.selected = [];
        //////////////////////////////////
        ////file system
        //////////////////////////////////
        this.root = new Directory('');
        // --- manage file events
        this._emitter = new vscode.EventEmitter();
        this._bufferedEvents = [];
        this.onDidChangeFile = this._emitter.event;
    }
    hasChildren(item) {
        if (item.collapsibleState === vscode.TreeItemCollapsibleState.Collapsed || item.collapsibleState === vscode.TreeItemCollapsibleState.Expanded) {
            return true;
        }
        return false;
    }
    getChildDepth(uri) {
        let folderpath = uri.path;
        if (folderpath[0] === "/" || folderpath[0] === "\\") {
            folderpath = folderpath.substring(1);
        }
        return folderpath.split(/[\\|/]/).length;
    }
    updateTreeViewMode() {
        if (this.treeViewMode === interfaces_1.TreeViewModes.normalMode) {
            this.treeViewMode = interfaces_1.TreeViewModes.selectMode;
        }
        else {
            this.treeViewMode = interfaces_1.TreeViewModes.normalMode;
        }
        this.refresh();
    }
    onClickItem(element) {
        this.updateCheckBox(element);
    }
    getTreeItem(element) {
        if (element.collapsibleState === vscode_1.TreeItemCollapsibleState.Collapsed || element.collapsibleState === vscode_1.TreeItemCollapsibleState.Expanded) {
            if (this.getChildDepth(element.pathUri) === 1) {
                element.contextValue = "serverInstance";
            }
            else {
                element.contextValue = "folder";
            }
            return element;
        }
        const treeItem = new vscode.TreeItem(element.label ?? "", element.collapsibleState);
        if (this.treeViewMode === interfaces_1.TreeViewModes.normalMode) {
            treeItem.iconPath = path.join(__filename, '..', '..', 'media', 'logo.svg');
            treeItem.command = element.command;
            treeItem.contextValue = "normal";
            element.checked = false;
        }
        else {
            treeItem.command = {
                command: "graylog.treeItemClick",
                title: 'Click',
                arguments: [element]
            };
            if (element.checked) {
                treeItem.contextValue = "treeItemContext";
                treeItem.iconPath = path.join(__filename, '..', '..', 'resources', 'checkbox-check.svg');
            }
            else {
                treeItem.contextValue = "normalTreeItem";
                treeItem.iconPath = path.join(__filename, '..', '..', 'resources', 'checkbox-blank.svg');
            }
        }
        let index = this.selected.findIndex((item) => item.pathUri === element.pathUri);
        if (index === -1) {
            if (element.checked) {
                this.selected.push(element);
            }
        }
        else {
            if (!element.checked) {
                this.selected.splice(index, 1);
            }
        }
        return treeItem;
    }
    async getChildren(element) {
        try {
            if (element) {
                return Promise.resolve(this.getDepsInPackageJson(element.pathUri));
            }
            else {
                if (this.pathExists(this.workspaceRoot)) {
                    return Promise.resolve(this.getDepsInPackageJson(this.workspaceRoot));
                }
                else {
                    return Promise.resolve([]);
                }
            }
        }
        catch (error) {
            return Promise.resolve([]);
        }
    }
    getDepsInPackageJson(pathUri) {
        if (this.pathExists(pathUri)) {
            const toDep = (moduleName) => {
                if (moduleName[1] === vscode.FileType.Directory) {
                    return new MyTreeItem(moduleName[0], false, vscode.Uri.joinPath(pathUri, moduleName[0]), vscode.TreeItemCollapsibleState.Collapsed);
                }
                else {
                    return new MyTreeItem(moduleName[0], false, vscode.Uri.joinPath(pathUri, moduleName[0]), vscode.TreeItemCollapsibleState.None, {
                        command: "vscode.open",
                        title: 'openDocument',
                        arguments: [vscode.Uri.joinPath(pathUri, moduleName[0])]
                    }, path.join(__filename, '..', '..', 'media', 'logo.svg'));
                }
            };
            const items = [];
            this.readDirectory(pathUri).forEach((element) => {
                if (!element[0].endsWith('.json')) {
                    items.push(toDep(element));
                }
            });
            return items.sort((a, b) => {
                const getFileName = (pUri) => {
                    const paths = pUri.path.split(/[\\|/]/);
                    return paths[paths.length - 1];
                };
                const aName = getFileName(a.pathUri);
                const bName = getFileName(b.pathUri);
                if (aName.includes('.grule') && !bName.includes('.grule')) {
                    return 1;
                }
                if (!aName.includes('.grule') && bName.includes('.grule')) {
                    return -1;
                }
                return aName.localeCompare(bName);
            });
        }
        else {
            return [];
        }
    }
    getParent(element) {
        throw new Error('Method not implemented.');
    }
    resolveTreeItem(item, element, token) {
        throw new Error('Method not implemented.');
    }
    refresh(item) {
        setTimeout(() => {
            this._onDidChangeTreeData.fire(item);
        }, 500);
    }
    updateCheckBox(selected) {
        selected.checked = !selected.checked;
        this.refresh(selected);
    }
    // --- manage file metadata
    stat(uri) {
        return this._lookup(uri, false);
    }
    readDirectory(uri) {
        const entry = this._lookupAsDirectory(uri, false);
        const result = [];
        for (const [name, child] of entry.entries) {
            result.push([name, child.type]);
        }
        return result;
    }
    // --- manage file contents
    readFile(uri) {
        const data = this._lookupAsFile(uri, false).data;
        if (data) {
            return data;
        }
        throw vscode.FileSystemError.FileNotFound();
    }
    writeFile(uri, content, options) {
        const basename = path.posix.basename(uri.path);
        const parent = this._lookupParentDirectory(uri);
        let entry = parent.entries.get(basename);
        if (entry instanceof Directory) {
            throw vscode.FileSystemError.FileIsADirectory(uri);
        }
        if (!entry && !options.create) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        if (entry && options.create && !options.overwrite) {
            throw vscode.FileSystemError.FileExists(uri);
        }
        if (!entry) {
            entry = new File(basename);
            parent.entries.set(basename, entry);
            this._fireSoon({ type: vscode.FileChangeType.Created, uri });
        }
        entry.mtime = Date.now();
        entry.size = content.byteLength;
        entry.data = content;
        if (!uri.path.endsWith('.json')) {
            this._fireSoon({ type: vscode.FileChangeType.Changed, uri });
        }
    }
    // --- manage files/folders
    rename(oldUri, newUri, options) {
        if (!options.overwrite && this._lookup(newUri, true)) {
            throw vscode.FileSystemError.FileExists(newUri);
        }
        const entry = this._lookup(oldUri, false);
        const oldParent = this._lookupParentDirectory(oldUri);
        const newParent = this._lookupParentDirectory(newUri);
        const newName = path.posix.basename(newUri.path);
        oldParent.entries.delete(entry.name);
        entry.name = newName;
        newParent.entries.set(newName, entry);
        this._fireSoon({ type: vscode.FileChangeType.Deleted, uri: oldUri }, { type: vscode.FileChangeType.Created, uri: newUri });
    }
    delete(uri) {
        const dirname = uri.with({ path: path.posix.dirname(uri.path) });
        const basename = path.posix.basename(uri.path);
        const parent = this._lookupAsDirectory(dirname, false);
        if (!parent.entries.has(basename)) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        parent.entries.delete(basename);
        parent.mtime = Date.now();
        parent.size -= 1;
        this._fireSoon({ type: vscode.FileChangeType.Changed, uri: dirname }, { uri, type: vscode.FileChangeType.Deleted });
        this.refresh();
    }
    createDirectory(uri) {
        const basename = path.posix.basename(uri.path);
        const dirname = uri.with({ path: path.posix.dirname(uri.path) });
        const parent = this._lookupAsDirectory(dirname, false);
        const entry = new Directory(basename);
        parent.entries.set(entry.name, entry);
        parent.mtime = Date.now();
        parent.size += 1;
        this._fireSoon({ type: vscode.FileChangeType.Changed, uri: dirname }, { type: vscode.FileChangeType.Created, uri });
    }
    _lookup(uri, silent) {
        const parts = uri.path.split('/');
        let entry = this.root;
        for (const part of parts) {
            if (!part) {
                continue;
            }
            let child;
            if (entry instanceof Directory) {
                child = entry.entries.get(part);
            }
            if (!child) {
                if (!silent) {
                    throw vscode.FileSystemError.FileNotFound(uri);
                }
                else {
                    return undefined;
                }
            }
            entry = child;
        }
        return entry;
    }
    _lookupAsDirectory(uri, silent) {
        const entry = this._lookup(uri, silent);
        if (entry instanceof Directory) {
            return entry;
        }
        throw vscode.FileSystemError.FileNotADirectory(uri);
    }
    pathExists(uri) {
        try {
            this._lookupAsDirectory(uri, false);
            return true;
        }
        catch {
            return false;
        }
    }
    isDirectory(uri) {
        try {
            this._lookupAsDirectory(uri, false);
            return true;
        }
        catch {
            return false;
        }
    }
    _lookupAsFile(uri, silent) {
        const entry = this._lookup(uri, silent);
        if (entry instanceof File) {
            return entry;
        }
        throw vscode.FileSystemError.FileIsADirectory(uri);
    }
    _lookupParentDirectory(uri) {
        const dirname = uri.with({ path: path.posix.dirname(uri.path) });
        return this._lookupAsDirectory(dirname, false);
    }
    watch(_resource) {
        // ignore, fires for all changes...
        return new vscode.Disposable(() => { });
    }
    _fireSoon(...events) {
        this._bufferedEvents.push(...events);
        if (this._fireSoonHandle) {
            clearTimeout(this._fireSoonHandle);
        }
        this._fireSoonHandle = setTimeout(() => {
            this._emitter.fire(this._bufferedEvents);
            this._bufferedEvents.length = 0;
        }, 5);
    }
}
exports.GraylogFileSystemProvider = GraylogFileSystemProvider;
//# sourceMappingURL=fileSystemProvider.js.map