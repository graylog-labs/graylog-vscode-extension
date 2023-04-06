"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectionPart = void 0;
const vscode = require("vscode");
const axios_1 = require("axios");
class ConnectionPart {
    constructor(graylogFilesystem, secretStorage) {
        this.graylogFilesystem = graylogFilesystem;
        this.secretStorage = secretStorage;
        ///
        this.apiUrl = "";
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
        /*
        let response;
  
        let title = filename;
        try{
          response = await axios.post(
            `${this.apiUrl}/api/system/pipelines/rule`
            ,{
              title: title,
              source:newFileSource(title),
              description: title
            },
            {
              headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-By':this.token
              },
              auth: {
                username: this.token,
                password: this.accountPassword
              }
            }
          );
  
          if(response.status == 200){
            this.wrilteFile(response.data);
          }
        }catch(e){
          if(e.response?.data){
            vscode.window.showErrorMessage("Failed to create");
            this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${filename}.grule`));
          }
        }*/
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
        /*
              let dindex = this.grules.findIndex((rule)=>{return rule.title == title});
              if(dindex == -1)
                return;
              
              
              let id = this.grules[dindex].id;
              let rulesource =await this.GetRuleSource(id);
              rulesource['source']=document.getText();
              delete rulesource['errors'];
        
              let response;
        
              let result:sourceError[] =[];
              try{
                response = await axios.put(
                  `${this.apiUrl}/api/system/pipelines/rule/${id}`
                  ,rulesource,
                  {
                    headers: {
                      Accept: 'application/json',
                      'Content-Type': 'application/json',
                      'X-Requested-By':this.token
                    },
                    auth: {
                      username: this.token,
                      password: this.accountPassword
                    }
                  }
                );
              }catch(e){
                if(e.response?.data){
                
                  e.response.data.map((edata:any)=>{
                    let tempdata:sourceError ={
                      type: edata['type'],
                      line: edata['line'],
                      reason:edata['reason'],
                      position_in_line: edata['position_in_line']
                    };
                    result.push(tempdata);
                  });
                }
              }
        
        
              this.errors = result;
        
              let ranges:vscode.Range[]=[];
              let decorationOptions:vscode.DecorationOptions[] = [];
        
              result.map((oneresult)=>{
                let line = oneresult.line-1;
                let indexOf = oneresult.position_in_line;
                // let position = new vscode.Position(line, indexOf +1 );
                let position = new vscode.Position(line, 1 );
                let position1 = new vscode.Position(line, 10 );
                // document.getWordRangeAtPosition(position)
                let range = new vscode.Range(position,position1);
                if(range) {
                  ranges.push(range);
                  const decInstanceRenderOptions: DecorationInstanceRenderOptions = {
                    after: {
                      contentText: truncateString(" "+oneresult.reason,40),
                      color: errorForeground,
                      backgroundColor: errorMessageBackground
                    },
                    light:{
                      after:{
                        backgroundColor: errorBackgroundLight,
                        color: errorForegroundLight
                      }
                    },
                  };
                  decorationOptions.push({
                    range,
                    renderOptions: decInstanceRenderOptions ,
                  });
        
                }
                  
              });
        
        
              vscode.window.activeTextEditor?.setDecorations(icon,decorationOptions); */
    }
    async GetRuleSource(id) {
        /*try{
          const response = await axios.get(`${this.apiUrl}/api/system/pipelines/rule/${id}`, {
            headers: {
              'Accept': 'application/json'
            },
            auth: {
              username: this.token,
              password: this.accountPassword
            }
          });
  
          return response.data;
        }catch(e){
        }*/
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
        // if(initapiurl.length==0)
        //   initapiurl = await vscode.window.showInputBox({
        //     placeHolder: 'Please type Graylog API Url',
        //     ignoreFocusOut: true,
        //     prompt:'Type your api url (http://10.10.10.10)'
        //   }) ?? "";
        //   if(!(await this.testAPI(initapiurl)))
        //   {
        //     vscode.window.showErrorMessage("API url is not valid.");
        //     initapiurl = "";
        //     continue;
        //   }
        //   if(initapiurl.substring(initapiurl.length-1) == "/" || initapiurl.substring(initapiurl.length-1) == "\\"){
        //     initapiurl = initapiurl.substring(0,initapiurl.length-1);
        //   }
        //   if(inittoken =="")
        //     inittoken = await vscode.window.showInputBox({
        //       placeHolder: 'Plz type the token',
        //       ignoreFocusOut: true,
        //       prompt:'plz type your graylog token'
        //     }) ?? "";
        //   if(inittoken == ""){
        //     vscode.window.showErrorMessage("Token cannot be empty");
        //     continue;
        //   }
        //   if(!await this.testUserInfo(initapiurl,inittoken)){
        //     vscode.window.showErrorMessage("User Info is not valid");
        //     inittoken = "";
        //     continue;
        //   }
        //   this.token = inittoken;
        //   if(initapiurl.includes("/api")){
        //     this.apiUrl = initapiurl.substring(0,initapiurl.indexOf("/api"))
        //   }else{
        //     this.apiUrl = initapiurl;
        //   }
        //   await this.secretStorage.store("graylogtoken",this.token);
        //   await this.secretStorage.store("graylogurl",this.apiUrl);
        //   break;
        // await this.secretStorage.store("reloaded","no");
        // vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });
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
        let tempArray = [];
        tempArray.push({
            title: rule['title'],
            id: rule['id'],
            description: rule['description'],
        });
        this.grules.push(tempArray);
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
            let rules = await this.GetAllRules(this.apis['apiInfoList'][num]['apiHostUrl'], this.apis['apiInfoList'][num]['token']);
            rules.map((rule) => {
                this.wrilteFile(num, rule);
            });
        });
    }
    async GetAllRules(url, token) {
        //      await this.restoreUserInfo();
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
        // if(await this.secretStorage.get("reloaded") != "yes"){
        //   this.LoginInitialize();
        // }
    }
    /*
    public async refreshWorkspace(){
      let tempRules = await this.GetAllRules();
      tempRules.forEach((tmpRule)=>{
        let fIdx = this.grules.findIndex((rule)=> rule['title'] == tmpRule['title']);
        if(fIdx > -1){
          this.updateRule(this.grules[fIdx],tmpRule);
        }else{
          this.wrilteFile(tmpRule);
        }
      });

    }
*/
    readRule(filePath) {
        return this.graylogFilesystem.readFile(vscode.Uri.parse(`graylog:/${filePath}.grule`));
    }
    updateRule(registeredRule, updatedRule) {
        let readdata = "";
        if (updatedRule['source'] != (readdata = this.readRule(registeredRule.title).toString())) {
            this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${registeredRule['title']}.grule`), Buffer.from(updatedRule['source']), { create: true, overwrite: true });
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