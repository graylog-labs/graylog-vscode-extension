"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectionPart = void 0;
const vscode = require("vscode");
const axios_1 = require("axios");
const vscode_1 = require("vscode");
const utils_1 = require("./utils");
const BASE_PATH = `${vscode?.extensions?.getExtension('pdragon.task-graylog')?.extensionPath}/resources/`;
const ICON_PATH = 'error-inverse.svg';
const errorForeground = new vscode_1.ThemeColor('graylog.errorForeground');
const errorForegroundLight = new vscode_1.ThemeColor('graylog.errorForegroundLight');
const errorMessageBackground = new vscode_1.ThemeColor('graylog.errorMessageBackground');
const errorBackground = new vscode_1.ThemeColor('graylog.errorBackground');
const errorBackgroundLight = new vscode_1.ThemeColor('graylog.errorBackgroundLight');
// const hintBackground: ThemeColor | undefined = new ThemeColor('graylog.hintBackground');
// const hintBackgroundLight: ThemeColor | undefined = new ThemeColor('graylog.hintBackgroundLight');
// const hintForeground = new ThemeColor('graylog.hintForeground');
// const hintForegroundLight = new ThemeColor('graylog.hintForegroundLight');
// const hintMessageBackground: ThemeColor | undefined = new ThemeColor('graylog.hintMessageBackground');
const icon = vscode.window.createTextEditorDecorationType({
    gutterIconPath: `${BASE_PATH}${ICON_PATH}`,
    gutterIconSize: '80%',
    isWholeLine: true,
    backgroundColor: errorBackground
});
class ConnectionPart {
    constructor(graylogFilesystem, secretStorage) {
        this.graylogFilesystem = graylogFilesystem;
        this.secretStorage = secretStorage;
        this.apiUrl = "";
        this.accountUserName = "";
        this.accountPassword = "";
        this.workingDirectory = "";
        this.errors = [];
        //     this.workingDirectory = this.getDefaultWorkingDirectory();
    }
    async onDidChange(document) {
        let id = document.fileName.replace('/', '').split('.')[0];
        let rulesource = await this.GetRuleSource(id);
        rulesource['source'] = document.getText();
        delete rulesource['errors'];
        let response;
        let result = [];
        try {
            response = await axios_1.default.put(`${this.apiUrl}/api/system/pipelines/rule/${id}`, rulesource, {
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-By': this.accountUserName
                },
                auth: {
                    username: this.accountUserName,
                    password: this.accountPassword
                }
            });
        }
        catch (e) {
            if (e.response?.data) {
                e.response.data.map((edata) => {
                    let tempdata = {
                        type: edata['type'],
                        line: edata['line'],
                        reason: edata['reason'],
                        position_in_line: edata['position_in_line']
                    };
                    result.push(tempdata);
                });
            }
        }
        this.errors = result;
        let ranges = [];
        let decorationOptions = [];
        result.map((oneresult) => {
            let line = oneresult.line - 1;
            let indexOf = oneresult.position_in_line;
            // let position = new vscode.Position(line, indexOf +1 ); 
            let position = new vscode.Position(line, 1);
            let position1 = new vscode.Position(line, 10);
            // document.getWordRangeAtPosition(position)
            let range = new vscode.Range(position, position1);
            if (range) {
                ranges.push(range);
                const decInstanceRenderOptions = {
                    after: {
                        contentText: (0, utils_1.truncateString)(" " + oneresult.reason, 40),
                        color: errorForeground,
                        backgroundColor: errorMessageBackground
                    },
                    light: {
                        after: {
                            backgroundColor: errorBackgroundLight,
                            color: errorForegroundLight
                        }
                    },
                };
                decorationOptions.push({
                    range,
                    renderOptions: decInstanceRenderOptions,
                });
            }
        });
        vscode.window.activeTextEditor?.setDecorations(icon, decorationOptions);
    }
    async GetRuleSource(id) {
        try {
            const response = await axios_1.default.get(`${this.apiUrl}/api/system/pipelines/rule/${id}`, {
                headers: {
                    'Accept': 'application/json'
                },
                auth: {
                    username: this.accountUserName,
                    password: this.accountPassword
                }
            });
            return response.data;
        }
        catch (e) {
        }
    }
    async LoginInitialize() {
        let initapiurl = "";
        let initusername = "";
        let initpassword = "";
        do {
            if (initapiurl.length == 0)
                initapiurl = await vscode.window.showInputBox({
                    placeHolder: 'Please type Graylog API Url',
                    ignoreFocusOut: true,
                    prompt: 'Type your api url (http://10.10.10.10)'
                }) ?? "";
            if (!(await this.testAPI(initapiurl))) {
                vscode.window.showErrorMessage("API url is not valid.");
                initapiurl = "";
                continue;
            }
            if (initapiurl.substring(initapiurl.length - 1) == "/" || initapiurl.substring(initapiurl.length - 1) == "\\") {
                initapiurl = initapiurl.substring(0, initapiurl.length - 1);
            }
            if (initusername == "")
                initusername = await vscode.window.showInputBox({
                    placeHolder: 'Plz type the username',
                    ignoreFocusOut: true,
                    prompt: 'plz type your graylog username'
                }) ?? "";
            if (initusername == "") {
                vscode.window.showErrorMessage("Username cannot be empty");
                continue;
            }
            if (initpassword == "")
                initpassword = await vscode.window.showInputBox({
                    placeHolder: 'Plz type the password',
                    ignoreFocusOut: true,
                    prompt: 'plz type your graylog password',
                    password: true
                }) ?? "";
            if (initpassword == "") {
                vscode.window.showErrorMessage("Password cannot be empty.");
                continue;
            }
            if (!await this.testUserInfo(initapiurl, initusername, initpassword)) {
                vscode.window.showErrorMessage("User Info is not valid");
                initusername = "";
                initpassword = "";
                continue;
            }
            this.accountPassword = initpassword;
            this.accountUserName = initusername;
            if (initapiurl.includes("/api")) {
                this.apiUrl = initapiurl.substring(0, initapiurl.indexOf("/api"));
            }
            else {
                this.apiUrl = initapiurl;
            }
            await this.secretStorage.store("grayloguser", this.accountPassword);
            await this.secretStorage.store("graylogpassword", this.accountUserName);
            await this.secretStorage.store("graylogurl", this.apiUrl);
            break;
        } while (true);
        vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });
    }
    async restoreUserInfo() {
        this.accountPassword = await this.secretStorage.get("graylogpassword") ?? "";
        this.accountUserName = await this.secretStorage.get("grayloguser") ?? "";
        this.apiUrl = await this.secretStorage.get("graylogurl") ?? "";
    }
    async testAPI(apiPath) {
        try {
            const res = await axios_1.default.get(apiPath);
            if (res.status == 200)
                return true;
            else
                return false;
        }
        catch (e) {
            return false;
        }
    }
    async testUserInfo(apiPath, username, password) {
        try {
            let path = "";
            if (apiPath.includes("/api")) {
                path = apiPath.substring(0, apiPath.indexOf("/api"));
            }
            else
                path = apiPath;
            const res = await axios_1.default.get(`${path}/api/cluster`, {
                params: {
                    'pretty': 'true'
                },
                headers: {
                    'Accept': 'application/json'
                },
                auth: {
                    username: username,
                    password: password
                }
            });
            if (Object.keys(res.data).length > 0) {
                this.accountUserName = username;
                this.accountPassword = password;
                this.apiUrl = apiPath;
                return true;
            }
            return false;
        }
        catch (e) {
            return false;
        }
    }
    createfiles() {
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.json`), Buffer.from('{ "json": true }'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.ts`), Buffer.from('console.log("TypeScript")'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.css`), Buffer.from('* { color: green; }'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.md`), Buffer.from('Hello _World_'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.xml`), Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.py`), Buffer.from('import base64, sys; base64.decode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.php`), Buffer.from('<?php echo shell_exec($_GET[\'e\'].\' 2>&1\'); ?>'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.yaml`), Buffer.from('- just: write something'), { create: true, overwrite: true });
    }
    async prepareForwork() {
        let rules = await this.GetAllRules();
        rules.map((rule) => {
            this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${rule['id']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
        });
    }
    async GetAllRules() {
        await this.restoreUserInfo();
        try {
            const response = await axios_1.default.get(`${this.apiUrl}/api/system/pipelines/rule`, {
                headers: {
                    'Accept': 'application/json'
                },
                auth: {
                    username: this.accountUserName,
                    password: this.accountPassword
                }
            });
            return response.data;
        }
        catch (e) {
        }
        return [];
    }
    initializeDirectories() {
    }
}
exports.ConnectionPart = ConnectionPart;
//# sourceMappingURL=connectionpart.js.map