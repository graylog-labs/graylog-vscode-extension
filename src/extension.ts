'use strict';

import * as vscode from 'vscode';

import { DepNodeProvider, Item } from './nodeDependencies';
import { ConnectionPart } from './connectionpart';
import {GraylogFileSystemProvider} from './fileSystemProvider';
import { CodelensProvider } from './CodelensProvider';
const colorData = require('../themes/color');



export function activate(context: vscode.ExtensionContext) {


	const Graylog = new GraylogFileSystemProvider();
	
	const connectpart= new ConnectionPart(Graylog,context.secrets);
	
	addColorSettings();
	
	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
	let initialized = false;

	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
		connectpart.clearworkspace();
	}));

	
	prepareForWork(connectpart,context.secrets);

	vscode.workspace.onDidChangeTextDocument((e)=>{
		if(connectpart.apiUrl!="")
			connectpart.onDidChange(e.document);
	});
	
	vscode.window.onDidChangeActiveTextEditor(e=>{
		if(connectpart.apiUrl!="" && e?.document)
			connectpart.onDidChange(e?.document);
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
		const config = vscode.workspace.getConfiguration() ;
		let tokenColorCustomizations = config.inspect('editor.tokenColorCustomizations')?.globalValue;

		const tokenColor = [];
		const colorDataLength = colorData.length;
		const tokenColorLength = tokenColor.length;

		for (let i = 0; i < colorDataLength; i++) {
			const name = colorData[i].name;

			let exist = false;
			for (let j = 0; j < tokenColorLength; j++) {
				if (tokenColor[j].name === name) {
					exist = true;
					break;
				}
			}

			if (!exist) {
				tokenColor.push(colorData[i]);
			}
		}

		await config.update(
			'editor.tokenColorCustomizations',
			tokenColorCustomizations,
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