'use strict';

import * as vscode from 'vscode';

import { DepNodeProvider, Item } from './nodeDependencies';
import { ConnectionPart } from './connectionpart';
import {GraylogFileSystemProvider} from './fileSystemProvider';

export function activate(context: vscode.ExtensionContext) {

	const graylogFilesystem=new GraylogFileSystemProvider();
	const connectionpart = new ConnectionPart(graylogFilesystem);
	
	const rootPath = (vscode.workspace.workspaceFolders && (vscode.workspace.workspaceFolders.length > 0))
		? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined;

	
	vscode.workspace.registerFileSystemProvider('graylog',graylogFilesystem );
	

	const nodeDependenciesProvider = new DepNodeProvider(rootPath);
	vscode.window.registerTreeDataProvider('nodeDependencies', nodeDependenciesProvider);
	

	vscode.commands.registerCommand('nodeDependencies.openDocument',(openpath)=>{
		vscode.workspace.openTextDocument(openpath).then(doc=>{
			vscode.window.showTextDocument(doc);
		});
	});
	vscode.commands.registerCommand('nodeDependencies.refreshEntry', () => nodeDependenciesProvider.refresh());
}