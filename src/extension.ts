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

//	const codelensProvider = new CodelensProvider(connectpart);

//	vscode.languages.registerCodeLensProvider("*",codelensProvider);
	
	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', Graylog, { isCaseSensitive: true }));
	let initialized = false;

	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.workspaceInit', async () => {
		
		await connectpart.LoginInitialize();
	}));

	if(vscode.workspace.workspaceFolders &&  vscode.workspace.workspaceFolders.length >0 && vscode.workspace.workspaceFolders[0].name == 'Graylog API')
	{
		connectpart.prepareForwork();
	}

	vscode.workspace.onDidChangeTextDocument((e)=>{
		if(connectpart.accountUserName!="")
			connectpart.onDidChange(e.document);
	});

}

/*

function addColorSettings() {
	(async () => {
		const config = vscode.workspace.getConfiguration() ;
		let tokenColorCustomizations = config.inspect('editor.tokenColorCustomizations')?.globalValue

		if (!tokenColorCustomizations) {
			tokenColorCustomizations = {};
		}
		if (!Object.hasOwnProperty.call(tokenColorCustomizations, 'textMateRules')) {
			tokenColorCustomizations['textMateRules'] = [];
		}

		const tokenColor = tokenColorCustomizations['textMateRules'];
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