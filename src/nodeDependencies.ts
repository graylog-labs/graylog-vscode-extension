import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export class DepNodeProvider implements vscode.TreeDataProvider<Item> {

	private _onDidChangeTreeData: vscode.EventEmitter<Item | undefined | void> = new vscode.EventEmitter<Item | undefined | void>();
	readonly onDidChangeTreeData: vscode.Event<Item | undefined | void> = this._onDidChangeTreeData.event;

	constructor(private workspaceRoot: string | undefined) {
	}

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: Item): vscode.TreeItem {
		return element;
	}

	getChildren(element?: Item): Thenable<Item[]> {
		if (!this.workspaceRoot) {
			vscode.window.showInformationMessage('No Item in empty workspace');
			return Promise.resolve([]);
		}

		if (element) {
			return Promise.resolve(this.getDepsInPackageJson(element.pathStr));
		} else {
			
			if (this.pathExists(this.workspaceRoot)) {
				return Promise.resolve(this.getDepsInPackageJson(this.workspaceRoot));
			} else {
				vscode.window.showInformationMessage('Workspace has no package.json');
				return Promise.resolve([]);
			}
		}

	}
	/**
	 * Given the path to package.json, read all its dependencies and devDependencies.
	 */
	private getDepsInPackageJson(pathStr: string): Item[] {
		const workspaceRoot = this.workspaceRoot;
		if (this.pathExists(pathStr) && workspaceRoot) {
			const toDep = (moduleName: string): Item => {
				if (fs.lstatSync(path.join(pathStr,moduleName)).isDirectory()) {
					return new Item(path.join(pathStr,moduleName),moduleName, vscode.TreeItemCollapsibleState.Collapsed);
				} else {
					return new Item(path.join(pathStr,moduleName),moduleName, vscode.TreeItemCollapsibleState.None, {
						command: "nodeDependencies.openDocument",
						title: 'openDocument',
						arguments: [path.join(pathStr,moduleName)]
					});
				}
			};

			const items = fs.readdirSync(pathStr).map(str => toDep(str));
			return items;
		} else {
			return [];
		}
	}

	private pathExists(p: string): boolean {
		try {
			fs.accessSync(p);
		} catch (err) {
			return false;
		}

		return true;
	}
}

export class Item extends vscode.TreeItem {

	constructor(
		public readonly pathStr: string,
		public readonly label: string,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState,
		public readonly command?: vscode.Command
	) {
		super(label, collapsibleState);

		this.tooltip = `${this.label}`;
	}

	iconPath = {
		light: path.join(__filename, '..', '..', 'resources', 'light', 'dependency.svg'),
		dark: path.join(__filename, '..', '..', 'resources', 'dark', 'dependency.svg')
	};

	contextValue = 'dependency';
}
