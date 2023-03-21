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

		// most common files types
		Graylog.writeFile(vscode.Uri.parse(`graylog:/file.txt`), Buffer.from('foo'), { create: true, overwrite: true });
		Graylog.writeFile(vscode.Uri.parse(`graylog:/file.html`), Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'), { create: true, overwrite: true });
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

	context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders( e =>{
		let a= "1";
	}));

	context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async() => {
		let apiurl:string = "";
		let username:string = "";
		let password:string = "";
		
		do{
			
			if(apiurl.length==0)
				apiurl = await vscode.window.showInputBox({
					placeHolder: 'Please type Graylog API Url',
					ignoreFocusOut: true
				}) ?? "";

			if(!(await connectpart.testAPI(apiurl)))
			{
				vscode.window.showErrorMessage("API url is not valid.");
				apiurl = "";
				continue;
			}
			if(username =="")
				username = await vscode.window.showInputBox({
					placeHolder: 'Plz type the username',
					ignoreFocusOut: true
				}) ?? "";

			if(username == ""){
				vscode.window.showErrorMessage("Username cannot be empty");
				continue;
			}

			if(password =="")
				password = await vscode.window.showInputBox({
					placeHolder: 'Plz type the password',
					ignoreFocusOut: true,
					password: true
				}) ?? "";
			if(password =="")
			{
				vscode.window.showErrorMessage("Password cannot be empty.");
				continue;
			}

			if(!await connectpart.testUserInfo(apiurl,username,password)){
				vscode.window.showErrorMessage("User Info is not valid");
				username = "";
				password = "";
				continue;
			}
			break;
		}while(true);

		vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });

		setTimeout(()=>{
			Graylog.createDirectory(vscode.Uri.parse(`graylog:/folder/`));
			Graylog.createDirectory(vscode.Uri.parse(`graylog:/large/`));
			Graylog.createDirectory(vscode.Uri.parse(`graylog:/xyz/`));
			Graylog.createDirectory(vscode.Uri.parse(`graylog:/xyz/abc`));
		},5000);
	}));
}


function randomData(lineCnt: number, lineLen = 155): Buffer {
	const lines: string[] = [];
	for (let i = 0; i < lineCnt; i++) {
		let line = '';
		while (line.length < lineLen) {
			line += Math.random().toString(2 + (i % 34)).substr(2);
		}
		lines.push(line.substr(0, lineLen));
	}
	return Buffer.from(lines.join('\n'), 'utf8');
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