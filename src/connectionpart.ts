import * as vscode from 'vscode';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import axios from 'axios';
import { DecorationInstanceRenderOptions } from 'vscode';
import { replaceLinebreaks, truncateString } from './utils';
import { newFileSource, errorForeground, errorMessageBackground, errorBackgroundLight, errorForegroundLight, icon} from './constants';
import {RuleField, sourceError} from './interfaces';



export class ConnectionPart{


    public apiUrl:string = "";
    public token = "";
    public accountPassword = "token";
    public workingDirectory="";
    public grules:RuleField[] =[];
    public errors:sourceError[]=[];
    public apiInfoList:any[] = [];
    constructor(private graylogFilesystem: GraylogFileSystemProvider,private readonly secretStorage:vscode.SecretStorage){
    }


    public async createRule(filename:string){
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
      }
    }
    public async onDidChange(document:vscode.TextDocument){
      let lIdx = document.fileName.lastIndexOf('/');
      let  fileName = document.fileName.substring(lIdx);
      let dIdx = fileName.lastIndexOf('.');
      let title= fileName.substring(0,dIdx);
      let extension = fileName.substring(dIdx);
      if(fileName == `graylogSetting.json`){
        let value = JSON.parse(document.getText());
      }
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


      vscode.window.activeTextEditor?.setDecorations(icon,decorationOptions);
    }

    public async GetRuleSource(id:string){
      try{
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
      }
    }
    public async LoginInitialize(){
      let initapiurl:string = "";
      let inittoken:string = "";
      
      let attemptCount = 0;
      do{
        
        attemptCount ++;
        if(attemptCount == 10){
          vscode.window.showInformationMessage("You tried many times. Plz try again a little later.");
          return;
        }

        if(initapiurl.length==0)
          initapiurl = await vscode.window.showInputBox({
            placeHolder: 'Please type Graylog API Url',
            ignoreFocusOut: true,
            prompt:'Type your api url (http://10.10.10.10)'
          }) ?? "";

          if(!(await this.testAPI(initapiurl)))
          {
            vscode.window.showErrorMessage("API url is not valid.");
            initapiurl = "";
            continue;
          }
          if(initapiurl.substring(initapiurl.length-1) == "/" || initapiurl.substring(initapiurl.length-1) == "\\"){
            initapiurl = initapiurl.substring(0,initapiurl.length-1);
          }

          if(inittoken =="")
            inittoken = await vscode.window.showInputBox({
              placeHolder: 'Plz type the token',
              ignoreFocusOut: true,
              prompt:'plz type your graylog token'
            }) ?? "";

          if(inittoken == ""){
            vscode.window.showErrorMessage("Token cannot be empty");
            continue;
          }

          if(!await this.testUserInfo(initapiurl,inittoken)){
            vscode.window.showErrorMessage("User Info is not valid");
            inittoken = "";
            continue;
          }

          this.token = inittoken;
          if(initapiurl.includes("/api")){
            this.apiUrl = initapiurl.substring(0,initapiurl.indexOf("/api"))
          }else{
            this.apiUrl = initapiurl;
          }

          await this.secretStorage.store("graylogtoken",this.token);
          await this.secretStorage.store("graylogurl",this.apiUrl);
          break;
        }while(true);

        await this.secretStorage.store("reloaded","no");
        vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });

    }

    public async restoreUserInfo(){
      this.token = await this.secretStorage.get("graylogtoken")??"";
      this.apiUrl = await this.secretStorage.get("graylogurl")??"";
    }
    public  async testAPI(apiPath:string):Promise<boolean>{
        try{
            const res  = await axios.get(apiPath);
            if(res.status == 200)
                return true;
            else return false;
        }catch(e){
            return false;
        }
    }

    public async testUserInfo(apiPath:string, username:string):Promise<boolean>{
        try{
            let path="";
            if(apiPath.includes("/api")){
                path = apiPath.substring(0,apiPath.indexOf("/api"));
            }else path = apiPath;

            const res  = await axios.get(`${path}/api/cluster`, {
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
              
              if(Object.keys(res.data).length > 0)
              {
                this.token = username;
                this.apiUrl = apiPath;
                return true;
              }  

              return false;
        }catch(e){
            return false;
        }
    }

    public wrilteFile(rule:any){
      

      let paths = rule['title'].split('/');
      let cumulative = "";
      if(paths.length > 1){
        for(let i=0;i<paths.length -1 ; i++){
          this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${cumulative}${paths[i]}`));
          cumulative +=(paths[i] + "/");
        }
      }
      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${rule['title']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
      this.grules.push({  
        title: rule['title'],
        id: rule['id'],
        description: rule['description'],
      });
    }
    
    public async prepareForwork(){
      let rules =await this.GetAllRules();
      rules.map((rule)=>{
        this.wrilteFile(rule);
      });
    }
    public async GetAllRules():Promise<[]>{
      await this.restoreUserInfo();
      try{
        const response = await axios.get(`${this.apiUrl}/api/system/pipelines/rule`, {
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
      }
      return [];
    }


    

    public async clearworkspace(){
      await this.secretStorage.store("reloaded","no");
      vscode.workspace.workspaceFolders?.map(async (folder, index)=>{
        if(folder.name == 'Graylog API'){
          await this.secretStorage.store("reloaded","yes");
          vscode.workspace.updateWorkspaceFolders(index,1);
        }
      });

      if(await this.secretStorage.get("reloaded") != "yes"){
        this.LoginInitialize();
      }
    }

    ////refresh from webUI interface
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

    public readRule(filePath: string){
      return this.graylogFilesystem.readFile(vscode.Uri.parse(`graylog:/${filePath}.grule`));
    }
    public updateRule(registeredRule:RuleField,updatedRule:any){
      let readdata="";
      if(updatedRule['source'] != (readdata=this.readRule(registeredRule.title).toString())){
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${registeredRule['title']}.grule`), Buffer.from(updatedRule['source']), { create: true, overwrite: true });
      }
    }

    //#region read and write apiInfo to storage
    public async readSettingApiInfo(){
      const apiData = JSON.parse(this.graylogFilesystem.readFile(vscode.Uri.parse(`graylog:/graylogSetting.json`)).toString());
      const apiCount = apiData["apiInfoList"].length ?? 0;
      await this.secretStorage.store("apiCount",apiCount);
      apiData["apiInfoList"].array.forEach(async (element:any,index:number) => {
        await this.secretStorage.store(`api_${index}_apiHost`,element["apiHost"]);
        await this.secretStorage.store(`api_${index}_token`,element["token"]);
        await this.secretStorage.store(`api_${index}_name`,element["name"]);
      });
    }

    public async readSettingApiInfoFromString(data: string){
      const apiData = JSON.parse(data);
      const apiCount = apiData["apiInfoList"].length ?? 0;
      await this.secretStorage.store("apiCount",apiCount);
      apiData["apiInfoList"].array.forEach(async (element:any,index:number) => {
        await this.secretStorage.store(`api_${index}_apiHost`,element["apiHost"]);
        await this.secretStorage.store(`api_${index}_token`,element["token"]);
        await this.secretStorage.store(`api_${index}_name`,element["name"]);
      });
    }

    public async writeSettingApiInfo(){
      const apis = [];
      const count = parseInt((await this.secretStorage.get("apiCount")) ?? "0");

      for(let i=0;i<count;i++){
        let tempApiHost = await this.secretStorage.get(`api_${i}_apiHost`);
        let tempToken = await this.secretStorage.get(`api_${i}_token`);
        let tempName = await this.secretStorage.get(`api_${i}_name`);
        apis.push({
          "apiHost":tempApiHost,
          "token": tempToken,
          "name": tempName
        });
      }

      this.apiInfoList = apis;

      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/graylogSetting.json`),Buffer.from( JSON.stringify({"apiInfoList":apis})), { create: true, overwrite: true });
      const doc =await vscode.workspace.openTextDocument(vscode.Uri.parse(`graylog:/graylogSetting.json`));
      await vscode.window.showTextDocument(doc);
    }
    //#endregion

  }