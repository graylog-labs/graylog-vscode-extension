import * as vscode from 'vscode';
const path = require('path');
import {Md5} from 'ts-md5';
/**
 * Cut off string if it's longer than provided number of characters.
 */
export function truncateString(str: string, max: number): string {
	const chars = [...str];
	return chars.length > max ? `${chars.slice(0, max).join('')}…` : str;
}
/**
 * Replace linebreaks with the one whitespace symbol.
 */
export function replaceLinebreaks(str: string, replaceSymbol: string): string {
	return str.replace(/[\n\r\t]+/g, replaceSymbol);
}
/**
 * Transform string svg to {@link Uri}
 */
export function svgToUri(svg: string): vscode.Uri {
	return vscode.Uri.parse(`data:image/svg+xml;utf8,${svg}`);
}
/**
 * To work on the web - use this instead of `path.basename`.
 */
export function basename(filePath: string): string {
	return filePath.split(/[\\/]/).pop() || '';
}


export function addColorSettings(colorData:any) {
	(async () => {
		const config = vscode.workspace.getConfiguration();
		await config.update(
			'editor.tokenColorCustomizations',
			colorData,
			vscode.ConfigurationTarget.Global,
		);
	})();
}

export function getPathSeparator():string{
	return path.sep;
}

export function getFormatedHashValue(inputString:string){
	const hashresult = Md5.hashStr(inputString);
	let tempResult = hashresult.split("");

	[23,18,13,8].forEach((index)=>{
		tempResult.splice(index,0,"-");
	});

	return tempResult.join("");
}