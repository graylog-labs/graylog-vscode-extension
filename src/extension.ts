'use strict';

import * as vscode from 'vscode';

import { ConnectionPart } from './graylog';
import {GraylogFileSystemProvider} from './fileSystemProvider';
import {addColorSettings} from './utils';
import { MyTreeItem } from './fileSystemProvider';

const colorData = require('../themes/color');

export function activate(context: vscode.ExtensionContext) {

	addColorSettings(colorData);
	
	const graylog = new GraylogFileSystemProvider();

	const connectpart = new ConnectionPart(graylog,context.secrets);

	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', graylog, { isCaseSensitive: true }));
	const treeview = vscode.window.createTreeView('graylog',{ treeDataProvider:graylog });	

	context.subscriptions.push(vscode.commands.registerCommand('graylog.RefreshWorkSpace', async () => {
		await connectpart.refreshWorkspace();
	}));
	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.showCreateInputBox', async () => {
		console.log('---------------');
	}));

	context.subscriptions.push(vscode.commands.registerCommand('graylog.treeItemClick',(item:MyTreeItem)=>{
		graylog.onClickItem(item);
	}));
	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.settingApiInfo', async () => {
		await connectpart.initSettings();
		connectpart.openSettings();
	}));

	context.subscriptions.push(vscode.commands.registerCommand( 'graylog.saveToLocal', (item:MyTreeItem) => {
		connectpart.saveToLocalFolder(item);
	}));

	context.subscriptions.push(vscode.commands.registerCommand( 'graylog.saveContentPack', () => {
		connectpart.saveActiveEditorContent();
	}));

	context.subscriptions.push( vscode.workspace.onDidSaveTextDocument((document)=>{
		if(document.fileName.endsWith("contentPack.json")){ vscode.commands.executeCommand("graylog.saveContentPack"); }
	}));

	context.subscriptions.push(vscode.commands.registerCommand( 'graylog.createNewRule', async (item:MyTreeItem) => {
		const value = await vscode.window.showInputBox({ prompt: 'Enter a value' });
		if(value) {
			connectpart.createNewRule( item, value);
		}
		// connectpart.createNewRule(item);
	}));
	

	context.subscriptions.push(vscode.commands.registerCommand('graylog.selectInstances',async ()=>{
		await connectpart.initSettings();
		const items=[];
		const quickItems = [];
		if(connectpart.apis.serverList && connectpart.apis.serverList.length > 0)
		{
			for(let i=0;i<connectpart.apis.serverList.length ;i++){
				items.push({
					label: connectpart.apis.serverList[i]['serverUrl'],
					index: i
				});
				quickItems.push(connectpart.apis.serverList[i]['serverUrl']);
			}
			const result = await vscode.window.showQuickPick(quickItems, { placeHolder: "Please select the server" });
			const resultIndex = quickItems.findIndex((item)=> item === result);
			  
			if (result && resultIndex > -1) {
				connectpart.clearworkspace({ label: result, index: resultIndex});
			}
		}
	}));
	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.MultiSelect', () => {
		graylog.updateTreeViewMode();
	}));

	const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
	statusBarItem.show();

	statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
	context.subscriptions.push(vscode.commands.registerCommand('graylog.setStatusBar', (text: string) => {
		statusBarItem.text = text;
	}));

	context.subscriptions.push(vscode.commands.registerCommand('graylog.exportToContext',async () => {
		///action for export to content pack
		await connectpart.createContentPack();
		vscode.commands.executeCommand("graylog.MultiSelect");
	}));

	vscode.workspace.onDidChangeTextDocument((e)=>{
		checkStatusBarShowing(e?.document.uri.scheme,statusBarItem);
		connectpart.onDidChange(e?.document);
	});
	
	vscode.window.onDidChangeActiveTextEditor(e=>{
		checkStatusBarShowing(e?.document.uri.scheme,statusBarItem);

		if(e?.document){
			connectpart.onDidChange(e?.document);
		}
	});

	vscode.window.onDidChangeVisibleTextEditors(event=>{
		if(vscode.window.activeTextEditor){
			checkStatusBarShowing(vscode.window.activeTextEditor?.document.uri.scheme,statusBarItem);
		}
		else { statusBarItem.hide(); }
	});

}



function checkStatusBarShowing( scheme: string | undefined, item: vscode.StatusBarItem ){
	if(!scheme) {
		return;
	}

	if( scheme === 'graylog'){
		item.show();
	}else{ item.hide(); }
}