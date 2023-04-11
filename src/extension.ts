'use strict';

import * as vscode from 'vscode';

import { ConnectionPart } from './graylog';
import {GraylogFileSystemProvider} from './fileSystemProvider';
import { CodelensProvider } from './CodelensProvider';
import {addColorSettings} from './utils';

const colorData = require('../themes/color');

export function activate(context: vscode.ExtensionContext) {

	addColorSettings(colorData);
	
	const graylog = new GraylogFileSystemProvider();

	const connectpart = new ConnectionPart(graylog,context.secrets);

	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('graylog', graylog, { isCaseSensitive: true }));
	const treeview = vscode.window.createTreeView('graylog',{ treeDataProvider:graylog });

	treeview.onDidChangeSelection((event)=>{
		const selected = event.selection[0];
		selected.checked = !selected.checked;
		graylog.updateCheckBox(selected);
	});

	context.subscriptions.push(vscode.commands.registerCommand('graylog.RereshWorkSpace', async () => {
		connectpart.refreshWorkspace();
	}));
	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.settingApiInfo', async () => {
		await connectpart.initSettings();
		connectpart.openSettings();
	}));

	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.selectInstances',async ()=>{
		await connectpart.initSettings();
		const items=[];
		if(connectpart.apis.apiInfoList && connectpart.apis.apiInfoList.length > 0)
		{
			for(let i=0;i<connectpart.apis.apiInfoList.length ;i++){
				items.push({
					label: connectpart.apis.apiInfoList[i]['apiHostUrl'],
					index: i
				});
			}
			const result = await vscode.window.showQuickPick(items, {
				canPickMany: true,
				placeHolder: 'Select Servers',
			  });
			  
			if (result) {
				connectpart.clearworkspace(result);
			}
		}
	}));
	
	context.subscriptions.push(vscode.commands.registerCommand('graylog.MultiSelect', () => {
		graylog.updateTreeViewMode();
	}));

	vscode.workspace.onDidChangeTextDocument((e)=>{
		connectpart.onDidChange(e?.document);
	});
	
	vscode.window.onDidChangeActiveTextEditor(e=>{
		if(e?.document){
			connectpart.onDidChange(e?.document);
		}
	});

	vscode.workspace.onDidCreateFiles((e)=>{
		e.files.map((file)=>{
			let name = file.path.replace("/","").split('.')[0];
			let extension = file.path.replace("/","").split('.')[1];
			if(file.scheme === 'graylog' && extension === 'grule'){
				connectpart.createRule(name);
			}
		});
	});

}



