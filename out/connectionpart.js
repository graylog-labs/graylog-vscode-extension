"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectionPart = void 0;
const vscode = require("vscode");
const axios_1 = require("axios");
const utils_1 = require("./utils");
const constants_1 = require("./constants");
class ConnectionPart {
    constructor(graylogFilesystem, secretStorage) {
        this.graylogFilesystem = graylogFilesystem;
        this.secretStorage = secretStorage;
        ///
        this.accountPassword = "token";
        this.workingDirectory = "";
        this.indexString = "";
        this.indexes = [];
        this.grules = [];
        this.errors = [];
        this.apiInfoList = [];
        this.apiSettingInfo = "";
    }
    async createRule(filename) {
        let response;
        const firstSlashIndex = filename.indexOf('/');
        const serverName = filename.substring(0, firstSlashIndex);
        const newRulename = filename.substring(firstSlashIndex + 1);
        const rootIndex = this.apis['apiInfoList'].findIndex((element) => {
            return element.name == serverName;
        });
        if (rootIndex == -1)
            return;
        let title = newRulename;
        try {
            response = await axios_1.default.post(`${this.apis['apiInfoList'][rootIndex].apiHostUrl}/api/system/pipelines/rule`, {
                title: title,
                source: (0, constants_1.newFileSource)(title),
                description: title
            }, {
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-By': this.apis['apiInfoList'][rootIndex].token
                },
                auth: {
                    username: this.apis['apiInfoList'][rootIndex].token,
                    password: this.accountPassword
                }
            });
            if (response.status == 200) {
                this.wrilteFile(rootIndex, response.data);
            }
        }
        catch (e) {
            if (e.response?.data) {
                vscode.window.showErrorMessage("Failed to create");
                this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${filename}.grule`));
            }
        }
    }
    async onDidChange(document) {
        let lIdx = document.fileName.lastIndexOf('/');
        let fileName = document.fileName.substring(lIdx + 1);
        let dIdx = fileName.lastIndexOf('.');
        let title = fileName.substring(0, dIdx);
        if (fileName == `graylogSetting.json`) {
            let value = "";
            try {
                if (value = JSON.parse(document.getText())) {
                    this.apis = value;
                    this.apiSettingInfo = document.getText();
                    this.writeSettingApiInfoToStorage(this.apiSettingInfo);
                }
            }
            catch (error) { }
            return;
        }
        const rootFolderName = document.fileName.split('/')[1];
        let rootIndex = this.apis["apiInfoList"].findIndex((info) => info['name'] == rootFolderName);
        if (rootIndex == -1)
            return;
        const gIndex = this.indexes.findIndex((iIndex) => {
            if (this.apis['apiInfoList'][iIndex]['name'] == rootFolderName)
                return true;
        });
        if (gIndex == -1)
            return;
        let dindex = this.grules[gIndex].findIndex((rule) => { return rule.title == title; });
        if (dindex == -1)
            return;
        let id = this.grules[gIndex][dindex].id;
        let rulesource = await this.GetRuleSource(rootIndex, id);
        rulesource['source'] = document.getText();
        delete rulesource['errors'];
        let response;
        let result = [];
        try {
            response = await axios_1.default.put(`${this.apis['apiInfoList'][rootIndex]['apiHostUrl']}/api/system/pipelines/rule/${id}`, rulesource, {
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-By': this.apis['apiInfoList'][gIndex]['token']
                },
                auth: {
                    username: this.apis['apiInfoList'][gIndex]['token'],
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
                        color: constants_1.errorForeground,
                        backgroundColor: constants_1.errorMessageBackground
                    },
                    light: {
                        after: {
                            backgroundColor: constants_1.errorBackgroundLight,
                            color: constants_1.errorForegroundLight
                        }
                    },
                };
                decorationOptions.push({
                    range,
                    renderOptions: decInstanceRenderOptions,
                });
            }
        });
        vscode.window.activeTextEditor?.setDecorations(constants_1.icon, decorationOptions);
    }
    async GetRuleSource(instanceIndex, id) {
        try {
            const response = await axios_1.default.get(`${this.apis['apiInfoList'][instanceIndex]['apiHostUrl']}/api/system/pipelines/rule/${id}`, {
                headers: {
                    'Accept': 'application/json'
                },
                auth: {
                    username: this.apis['apiInfoList'][instanceIndex]['token'],
                    password: this.accountPassword
                }
            });
            return response.data;
        }
        catch (e) {
        }
    }
    async LogInfoCheck(url, token) {
        // let initapiurl:string = "";
        // let inittoken:string = "";
        if (!(await this.testAPI(url))) {
            return false;
        }
        if (!await this.testUserInfo(url, token)) {
            return false;
        }
        return true;
    }
    // public async restoreUserInfo(){
    //   this.token = await this.secretStorage.get("graylogtoken")??"";
    //   this.apiUrl = await this.secretStorage.get("graylogurl")??"";
    // }
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
    async testUserInfo(apiPath, username) {
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
                    password: this.accountPassword
                }
            });
            if (Object.keys(res.data).length > 0) {
                return true;
            }
            return false;
        }
        catch (e) {
            return false;
        }
    }
    wrilteFile(rootIndex, rule) {
        let paths = rule['title'].split('/');
        let cumulative = "";
        let name = this.apis['apiInfoList'][rootIndex]['name'];
        if (paths.length > 1) {
            for (let i = 0; i < paths.length - 1; i++) {
                this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${name}/${cumulative}${paths[i]}`));
                cumulative += (paths[i] + "/");
            }
        }
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${name}/${rule['title']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
    }
    async prepareForwork() {
        this.indexString = await this.secretStorage.get("indexes");
        if (!this.indexString)
            return;
        const indexs = [];
        this.indexString.split(',').forEach(data => {
            indexs.push(parseInt(data));
        });
        this.indexes = indexs;
        indexs.forEach(async (num) => {
            this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][num]['name']}`));
            if (await this.LogInfoCheck(this.apis['apiInfoList'][num]['apiHostUrl'], this.apis['apiInfoList'][num]['token'])) {
                let rules = await this.GetAllRules(this.apis['apiInfoList'][num]['apiHostUrl'], this.apis['apiInfoList'][num]['token']);
                let tempArray = [];
                rules.map((rule) => {
                    this.wrilteFile(num, rule);
                    tempArray.push({
                        title: rule['title'],
                        id: rule['id'],
                        description: rule['description'],
                    });
                });
                this.grules.push(tempArray);
            }
        });
    }
    async GetAllRules(url, token) {
        try {
            const response = await axios_1.default.get(`${url}/api/system/pipelines/rule`, {
                headers: {
                    'Accept': 'application/json'
                },
                auth: {
                    username: token,
                    password: this.accountPassword
                }
            });
            return response.data;
        }
        catch (e) {
        }
        return [];
    }
    async clearworkspace(result) {
        this.indexString = "";
        const workSpaceFoldersToAdd = [];
        result.forEach(element => {
            if (this.indexString != undefined && this.indexString != null) {
                if (this.indexString.length > 0)
                    this.indexString += ",";
                this.indexString += element.index;
                workSpaceFoldersToAdd.push({
                    uri: vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][element.index]['name']}`),
                    name: this.apis['apiInfoList'][element.index]['name']
                });
            }
        });
        await this.secretStorage.store("indexes", this.indexString); // when vs code reloaded, restore the checked instances from this string
        await this.secretStorage.store("reloaded", "no");
        let removeCount = 0;
        vscode.workspace.workspaceFolders?.map(async (folder, index) => {
            if (folder.uri.toString().includes('graylog:/')) {
                removeCount++;
            }
        });
        vscode.workspace.updateWorkspaceFolders(0, removeCount, ...workSpaceFoldersToAdd);
    }
    async refreshWorkspace() {
        this.indexes.forEach(async (indexNum, index) => {
            let tempRules = await this.GetAllRules(this.apis['apiInfoList'][indexNum]['apiHostUrl'], this.apis['apiInfoList'][indexNum]['token']);
            tempRules.forEach((tmpRule) => {
                let fIdx = this.grules[index].findIndex((rule) => rule['title'] == tmpRule['title']);
                if (fIdx > -1) {
                    this.updateRule(indexNum, this.grules[index][fIdx], tmpRule);
                }
                else {
                    this.wrilteFile(indexNum, tmpRule);
                }
            });
        });
    }
    readRule(rootIndex, filePath) {
        return this.graylogFilesystem.readFile(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][rootIndex]['name']}/${filePath}.grule`));
    }
    updateRule(rootIndex, registeredRule, updatedRule) {
        let readdata = "";
        if (updatedRule['source'] != (readdata = this.readRule(rootIndex, registeredRule.title).toString())) {
            this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][rootIndex]['name']}/${registeredRule['title']}.grule`), Buffer.from(updatedRule['source']), { create: true, overwrite: true });
        }
    }
    //#region read and write apiInfo to storage
    async readSettingApiInfo() {
        const data = await this.secretStorage.get("graylogSetting");
        if (data) {
            this.apiSettingInfo = data;
        }
        else {
            this.apiSettingInfo = JSON.stringify({ "apiInfoList": [{ "apiHostUrl": "", "token": "", "name": "Development" }] });
        }
        this.apis = JSON.parse(this.apiSettingInfo);
    }
    async writeSettingApiInfoToStorage(apiInfo) {
        await this.secretStorage.store("graylogSetting", apiInfo);
    }
    writeSettingApiInfoToFileSystem() {
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/graylogSetting.json`), Buffer.from(this.apiSettingInfo), { create: true, overwrite: true });
    }
    async initSettings() {
        await this.readSettingApiInfo();
        this.writeSettingApiInfoToFileSystem();
    }
    async openSettings() {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(`graylog:/graylogSetting.json`));
        await vscode.window.showTextDocument(doc);
    }
}
exports.ConnectionPart = ConnectionPart;
//# sourceMappingURL=connectionpart.js.map