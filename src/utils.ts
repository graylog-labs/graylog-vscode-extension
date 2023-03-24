import { Uri } from 'vscode';

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
export function svgToUri(svg: string): Uri {
	return Uri.parse(`data:image/svg+xml;utf8,${svg}`);
}
/**
 * To work on the web - use this instead of `path.basename`.
 */
export function basename(filePath: string): string {
	return filePath.split(/[\\/]/).pop() || '';
}
