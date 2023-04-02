'use strict';

import * as vscode from 'vscode';

import { DepNodeProvider, Item } from './nodeDependencies';
import { ConnectionPart } from './connectionpart';
import {GraylogFileSystemProvider} from './fileSystemProvider';
import { CodelensProvider } from './CodelensProvider';

const colorData = require('../themes/color');
export function activate(context: vscode.ExtensionContext) {

	addColorSettings();
	const Graylog = new GraylogFileSystemProvider();
	
	const connectpart= new ConnectionPart(Graylog,context.secrets);
	
	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
	let initialized = false;

	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
		connectpart.clearworkspace();
	}));

	context.subscriptions.push(vscode.commands.registerCommand('graylog.RereshWorkSpace', async () => {
		connectpart.refreshWorkspace();
	}));
	
	prepareForWork(connectpart,context.secrets);

	vscode.workspace.onDidChangeTextDocument((e)=>{
		if(connectpart.apiUrl!="")
			// e?.document.save().then((result)=>{
			// 	if(result){
					connectpart.onDidChange(e?.document);
				// }
			// })
	});
	
	vscode.window.onDidChangeActiveTextEditor(e=>{
		if(connectpart.apiUrl!="" && e?.document)
			// e?.document.save().then((result)=>{
				// if(result){
					connectpart.onDidChange(e?.document);
				// }
			// })
	});

	vscode.workspace.onDidCreateFiles((e)=>{
		e.files.map((file)=>{
			let name = file.path.replace("/","").split('.')[0];
			let extension = file.path.replace("/","").split('.')[1];
			if(file.scheme == 'graylog' && extension == 'grule'){
				connectpart.createRule(name);
			}
		});
	});

}

async function prepareForWork(connectpart:ConnectionPart,secretStorage:vscode.SecretStorage){

	if(vscode.workspace.workspaceFolders &&  vscode.workspace.workspaceFolders.length >0 && vscode.workspace.workspaceFolders[0].name == 'Graylog API')
	{
		connectpart.prepareForwork();
	}

	if(await secretStorage.get("reloaded") == "yes"){
		connectpart.LoginInitialize();
	}
	
}


function addColorSettings() {
	(async () => {
		const config = vscode.workspace.getConfiguration();
		await config.update(
			'editor.tokenColorCustomizations',
			colorData,
			vscode.ConfigurationTarget.Global,
		);
	})();
}

// "views": {
// 	"package-explorer": [
// 	  {
// 		"id": "nodeDependencies",
// 		"name": "Node Dependencies",
// 		"icon": "media/dep.svg",
// 		"contextualTitle": "Package Explorer"
// 	  }
// 	]
//   },