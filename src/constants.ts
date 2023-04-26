import * as vscode from 'vscode';

export function newFileSource(title:string):string{
    return `rule "${title}"
    when
    // Set the conditions of your rule
    true
then
    // Develop the activities to take place within your rule
    // The Function documentation is here: 
    // https://go2docs.graylog.org/5-0/making_sense_of_your_log_data/functions_index.html

    // The Graylog Information Model (How to name your fields) is here:
    // https://schema.graylog.org

    // Thanks for using the Graylog VSCode Editor - Graylog Services Team
    
end`;
}

export const InitGraylogSettingInfo = 
`{
  "graylogSettings":[
    {
      "serverUrl": "",
      "token": "",
      "name": ""
    }
  ]
}`;

export const BASE_PATH = `${vscode?.extensions?.getExtension('pdragon.task-graylog')?.extensionPath}/resources/`;
export const ICON_PATH='error-inverse.svg';
export const errorForeground = new vscode.ThemeColor('graylog.errorForeground');
export const errorForegroundLight = new vscode.ThemeColor('graylog.errorForegroundLight');
export const errorMessageBackground: vscode.ThemeColor | undefined = new vscode.ThemeColor('graylog.errorMessageBackground');
export const errorBackground: vscode.ThemeColor | undefined = new vscode.ThemeColor('graylog.errorBackground');
export const errorBackgroundLight: vscode.ThemeColor | undefined = new vscode.ThemeColor('graylog.errorBackgroundLight');

export const icon = vscode.window.createTextEditorDecorationType({
  gutterIconPath:`${BASE_PATH}${ICON_PATH}`,
  gutterIconSize:'80%',
  isWholeLine: true,
  backgroundColor: errorBackground
});