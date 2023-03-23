'use strict';

import * as vscode from 'vscode';

import { DepNodeProvider, Item } from './nodeDependencies';
import { ConnectionPart } from './connectionpart';
import {GraylogFileSystemProvider} from './fileSystemProvider';
export function activate(context: vscode.ExtensionContext) {

	console.log('graylog says "Hello"');

	const Graylog = new GraylogFileSystemProvider();
	
	const connectpart= new ConnectionPart(Graylog);

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


	if(vscode.workspace.workspaceFolders &&  vscode.workspace.workspaceFolders.length >0 && vscode.workspace.workspaceFolders[0].name == 'Graylog API')
	{
		
		Graylog.writeFile(vscode.Uri.parse(`graylog:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
        Graylog.writeFile(vscode.Uri.parse(`graylog:/file.html`), Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'), { create: true, overwrite: true });
	}
}


/*
export function activate(context: vscode.ExtensionContext) {

	// const graylogFilesystem=new GraylogFileSystemProvider();
	
	// const connectionpart = new ConnectionPart(graylogFilesystem);

	// context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', graylogFilesystem, { isCaseSensitive: true }));

	// const rootPath = (vscode.workspace.workspaceFolders && (vscode.workspace.workspaceFolders.length > 0))
	// 	? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined;
	

	// const nodeDependenciesProvider = new DepNodeProvider(rootPath);
	// vscode.window.registerTreeDataProvider('nodeDependencies', nodeDependenciesProvider);
	

	// vscode.commands.registerCommand('nodeDependencies.openDocument',(openpath)=>{
	// 	vscode.workspace.openTextDocument(openpath).then(doc=>{
	// 		vscode.window.showTextDocument(doc);
	// 	});
	// });
	// vscode.commands.registerCommand('nodeDependencies.refreshEntry', () => nodeDependenciesProvider.refresh());
}*/