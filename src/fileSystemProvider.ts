/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/


import * as path from 'path';
import * as vscode from 'vscode';

import { TreeViewModes,createEditStatus } from './interfaces';

export class File implements vscode.FileStat {

	type: vscode.FileType;
	ctime: number;
	mtime: number;
	size: number;

	name: string;
	data?: Uint8Array;

	constructor(name: string) {
		this.type = vscode.FileType.File;
		this.ctime = Date.now();
		this.mtime = Date.now();
		this.size = 0;
		this.name = name;
	}
}

export class Directory implements vscode.FileStat {

	type: vscode.FileType;
	ctime: number;
	mtime: number;
	size: number;

	name: string;
	entries: Map<string, File | Directory>;

	constructor(name: string) {
		this.type = vscode.FileType.Directory;
		this.ctime = Date.now();
		this.mtime = Date.now();
		this.size = 0;
		this.name = name;
		this.entries = new Map();
	}
}

export type Entry = File | Directory;

import { TreeItem, TreeItemCollapsibleState } from 'vscode';

export class MyTreeItem extends vscode.TreeItem {
  constructor(label: string, checked: boolean,pathUri: vscode.Uri, state: vscode.TreeItemCollapsibleState,public readonly command?: vscode.Command,public readonly iconPath?:string) {
    super(label, TreeItemCollapsibleState.Collapsed);
	this.collapsibleState = state;
	this.pathUri = pathUri;
    this.command = command;
	this.iconPath = iconPath;
	this.checked = checked;
  }
  checked: boolean;
  pathUri: vscode.Uri;
}

export class GraylogFileSystemProvider implements vscode.FileSystemProvider,vscode.TreeDataProvider<MyTreeItem> {
	
	public treeViewMode:TreeViewModes = TreeViewModes.normalMode;

	private _onDidChangeTreeData: vscode.EventEmitter<void | MyTreeItem | MyTreeItem[] | null | undefined> = new vscode.EventEmitter<void | MyTreeItem | MyTreeItem[] | null | undefined>();
	readonly onDidChangeTreeData: vscode.Event<void | MyTreeItem | MyTreeItem[] | null | undefined> = this._onDidChangeTreeData.event;
	
	workspaceRoot: vscode.Uri= vscode.Uri.parse('graylog:/');
    createEditStatus:createEditStatus = createEditStatus.normal;
	createEditItem?:MyTreeItem;

	selected: MyTreeItem[]=[];
	hasChildren(item:MyTreeItem):boolean{
		if(item.collapsibleState === vscode.TreeItemCollapsibleState.Collapsed || item.collapsibleState === vscode.TreeItemCollapsibleState.Expanded){
		  return true;
		}
		return false;
	}

	getChildDepth(uri:vscode.Uri):number{
		let folderpath = uri.path;
		if(folderpath[0] === "/" || folderpath[0] === "\\"){
			folderpath = folderpath.substring(1);
		}

		return folderpath.split(/[\\|/]/).length;
	}

	updateTreeViewMode():void{
		if(this.treeViewMode === TreeViewModes.normalMode){
			this.treeViewMode = TreeViewModes.selectMode;
		}else{
			this.treeViewMode = TreeViewModes.normalMode;
		}
		this.refresh();
	}
	onClickItem(element:MyTreeItem){
		this.updateCheckBox(element);
	}


	getTreeItem(element: MyTreeItem): vscode.TreeItem | Thenable<vscode.TreeItem> {

		if(element.collapsibleState === TreeItemCollapsibleState.Collapsed || element.collapsibleState === TreeItemCollapsibleState.Expanded){
			if(this.getChildDepth(element.pathUri) === 1){
				element.contextValue = "serverInstance";
			}else{
				element.contextValue = "folder";
			}
			return element;
		}

		const treeItem = new vscode.TreeItem(element.label??"", element.collapsibleState);
		if(this.treeViewMode === TreeViewModes.normalMode){
			treeItem.iconPath = path.join(__filename,'..','..','media','logo.svg');
			treeItem.command = element.command;
			treeItem.contextValue = "normal";
			element.checked = false;
		}else{
			treeItem.command = {
				command: "graylog.treeItemClick",
				title: 'Click',
				arguments: [element]
			};

			if(element.checked){
				treeItem.contextValue = "treeItemContext";
				treeItem.iconPath = path.join(__filename,'..','..','resources','checkbox-check.svg');
			}else{
				treeItem.contextValue = "normalTreeItem";
				treeItem.iconPath = path.join(__filename,'..','..','resources','checkbox-blank.svg');
			}
		}

		let index = this.selected.findIndex((item)=>item.pathUri === element.pathUri);
		if(index === -1){
			if(element.checked){
				this.selected.push(element);
			}
		}else{
			if(!element.checked){
				this.selected.splice(index,1);
			}
		}

		return treeItem;
	}
	async getChildren(element?: MyTreeItem | undefined): Promise<MyTreeItem[]> {
		try {
			if (element) {
				return Promise.resolve(this.getDepsInPackageJson(element.pathUri));
			} else {
				if (this.pathExists(this.workspaceRoot)) {
					return Promise.resolve(this.getDepsInPackageJson(this.workspaceRoot));
				} else {
					return Promise.resolve([]);
				}
			}			
		} catch (error) {
			return Promise.resolve([]);
		}
	}

	private getDepsInPackageJson(pathUri: vscode.Uri): MyTreeItem[] {
		if (this.pathExists(pathUri)) {
			const toDep = (moduleName: [string, vscode.FileType]): MyTreeItem => {
				if(moduleName[1] === vscode.FileType.Directory){
					return new MyTreeItem(moduleName[0],false, vscode.Uri.joinPath(pathUri,moduleName[0]), vscode.TreeItemCollapsibleState.Collapsed);
				}else{
					return new MyTreeItem(moduleName[0],false,vscode.Uri.joinPath(pathUri,moduleName[0]), vscode.TreeItemCollapsibleState.None, {
						command: "vscode.open",
						title: 'openDocument',
						arguments: [vscode.Uri.joinPath(pathUri, moduleName[0])]
					},path.join(__filename,'..','..','media','logo.svg'));
				}
			};

			const items: MyTreeItem[]= [];
			this.readDirectory(pathUri).forEach((element)=>{
				if( !element[0].endsWith('.json') ){
					items.push(toDep(element));
				}
			});

			return items.sort((a:MyTreeItem,b:MyTreeItem)=>{
				const getFileName = (pUri:vscode.Uri):string=>{
					const paths=pUri.path.split(/[\\|/]/);
					return paths[paths.length-1];
				};
				const aName= getFileName(a.pathUri);
				const bName = getFileName(b.pathUri);
				if(aName.includes('.grule') && !bName.includes('.grule')){
					return 1;
				}
				if(!aName.includes('.grule') && bName.includes('.grule')){
					return -1;
				}
				return aName.localeCompare(bName);
			});
		} else {
			return [];
		}
	}

	getParent?(element: MyTreeItem): vscode.ProviderResult<MyTreeItem> {
		throw new Error('Method not implemented.');
	}
	
	resolveTreeItem?(item: vscode.TreeItem, element: MyTreeItem, token: vscode.CancellationToken): vscode.ProviderResult<vscode.TreeItem> {
		throw new Error('Method not implemented.');
	}
	
	public refresh(item?: MyTreeItem): void {
		setTimeout(()=>{
			this._onDidChangeTreeData.fire(item);          
        },500);
	}

	

	updateCheckBox(selected: MyTreeItem):void{
		selected.checked = !selected.checked;
		this.refresh(selected);
	}
	//////////////////////////////////
	////file system
	//////////////////////////////////
	root = new Directory('');

	// --- manage file metadata

	stat(uri: vscode.Uri): vscode.FileStat {
		return this._lookup(uri, false);
	}

	readDirectory(uri: vscode.Uri): [string, vscode.FileType][] {
		const entry = this._lookupAsDirectory(uri, false);
		const result: [string, vscode.FileType][] = [];
		for (const [name, child] of entry.entries) {
			result.push([name, child.type]);
		}
		return result;
	}

	// --- manage file contents

	readFile(uri: vscode.Uri): Uint8Array {
		const data = this._lookupAsFile(uri, false).data;
		if (data) {
			return data;
		}
		throw vscode.FileSystemError.FileNotFound();
	}

	writeFile(uri: vscode.Uri, content: Uint8Array, options: { create: boolean, overwrite: boolean }): void {
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

		if( !uri.path.endsWith('.json') ){
			this._fireSoon({ type: vscode.FileChangeType.Changed, uri });
		}

	}

	// --- manage files/folders

	rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean }): void {

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

		this._fireSoon(
			{ type: vscode.FileChangeType.Deleted, uri: oldUri },
			{ type: vscode.FileChangeType.Created, uri: newUri }
		);
	}

	delete(uri: vscode.Uri): void {
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

	createDirectory(uri: vscode.Uri): void {
		const basename = path.posix.basename(uri.path);
		const dirname = uri.with({ path: path.posix.dirname(uri.path) });
		const parent = this._lookupAsDirectory(dirname, false);

		const entry = new Directory(basename);
		parent.entries.set(entry.name, entry);
		parent.mtime = Date.now();
		parent.size += 1;
		this._fireSoon({ type: vscode.FileChangeType.Changed, uri: dirname }, { type: vscode.FileChangeType.Created, uri });
	}

	// --- lookup

	private _lookup(uri: vscode.Uri, silent: false): Entry;
	private _lookup(uri: vscode.Uri, silent: boolean): Entry | undefined;
	private _lookup(uri: vscode.Uri, silent: boolean): Entry | undefined {
		const parts = uri.path.split('/');
		let entry: Entry = this.root;
		for (const part of parts) {
			if (!part) {
				continue;
			}
			let child: Entry | undefined;
			if (entry instanceof Directory) {
				child = entry.entries.get(part);
			}
			if (!child) {
				if (!silent) {
					throw vscode.FileSystemError.FileNotFound(uri);
				} else {
					return undefined;
				}
			}
			entry = child;
		}
		return entry;
	}

	private _lookupAsDirectory(uri: vscode.Uri, silent: boolean): Directory {
		const entry = this._lookup(uri, silent);
		if (entry instanceof Directory) {
			return entry;
		}
		throw vscode.FileSystemError.FileNotADirectory(uri);
	}

	public pathExists(uri: vscode.Uri):boolean{
		try{
			this._lookupAsDirectory(uri,false);
			return true;
		}catch{
			return false;
		}
	}

	private isDirectory(uri:vscode.Uri):boolean{
		try{
			this._lookupAsDirectory(uri,false);
			return true;
		}catch{
			return false;
		}
	}
	private _lookupAsFile(uri: vscode.Uri, silent: boolean): File {
		const entry = this._lookup(uri, silent);
		if (entry instanceof File) {
			return entry;
		}
		throw vscode.FileSystemError.FileIsADirectory(uri);
	}

	private _lookupParentDirectory(uri: vscode.Uri): Directory {
		const dirname = uri.with({ path: path.posix.dirname(uri.path) });
		return this._lookupAsDirectory(dirname, false);
	}

	// --- manage file events

	private _emitter = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
	private _bufferedEvents: vscode.FileChangeEvent[] = [];
	private _fireSoonHandle?: NodeJS.Timer;

	readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._emitter.event;

	watch(_resource: vscode.Uri): vscode.Disposable {
		// ignore, fires for all changes...
		return new vscode.Disposable(() => { });
	}

	private _fireSoon(...events: vscode.FileChangeEvent[]): void {
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
