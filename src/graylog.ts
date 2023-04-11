import * as vscode from 'vscode';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import axios from 'axios';
import { DecorationInstanceRenderOptions } from 'vscode';
import { replaceLinebreaks, truncateString,getPathSeparator } from './utils';
import { newFileSource, errorForeground, errorMessageBackground, errorBackgroundLight, errorForegroundLight, icon} from './constants';
import {RuleField, sourceError, apiInstance} from './interfaces';



export class ConnectionPart{
  ////multi
    public apis:any;
  ///

    public accountPassword = "token";
    public workingDirectory="";
    indexes:number[]=[];
    public grules:RuleField[][] =[];
    public errors:sourceError[]=[];
    public apiInfoList:any[] = [];

    public apiSettingInfo:string = "";
    
    pathSeparator=getPathSeparator();
    
    constructor(private graylogFilesystem: GraylogFileSystemProvider,private readonly secretStorage:vscode.SecretStorage){
    }

    public async createRule(filename:string){
      let response; 

      const firstSlashIndex = filename.indexOf(this.pathSeparator);
      const serverName = filename.substring(0,firstSlashIndex);
      const newRulename = filename.substring(firstSlashIndex+1);
      const rootIndex = this.apis['apiInfoList'].findIndex((element:apiInstance)=>{
        return element.name === serverName;
      });
      if(rootIndex === -1) {
        return;
      }

      let title = newRulename;
      try{
        response = await axios.post(
          `${this.apis['apiInfoList'][rootIndex].apiHostUrl}/api/system/pipelines/rule`
          ,{
            title: title,
            source:newFileSource(title),
            description: title
          },
          {
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'X-Requested-By':this.apis['apiInfoList'][rootIndex].token
            },
            auth: {
              username: this.apis['apiInfoList'][rootIndex].token,
              password: this.accountPassword
            }
          }
        );

        if(response.status === 200){
          this.wrilteFile(rootIndex,response.data);
        }
      }catch(e){
        if(e.response?.data){
          vscode.window.showErrorMessage("Failed to create");
          this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${filename}.grule`));     
        }
      }
    }
    public async onDidChange(document:vscode.TextDocument){
      let lIdx = document.fileName.lastIndexOf(this.pathSeparator);
      let  fileName = document.fileName.substring(lIdx+1);
      if(fileName[0] === this.pathSeparator) {
        fileName = fileName.substring(1);
      }
      let dIdx = fileName.lastIndexOf('.');
      let title= fileName.substring(0,dIdx);
      
      if(fileName === `graylogSetting.json`){
         let value="";
         try {
          if(value = JSON.parse(document.getText())){
            this.apis = value;
            this.apiSettingInfo = document.getText();
            this.writeSettingApiInfoToStorage(this.apiSettingInfo);
           }
         } catch (error) {}
        return;
      }
      const rootFolderName = document.fileName.split(this.pathSeparator)[1];
      let rootIndex = this.apis["apiInfoList"].findIndex((info:any)=>info['name'] === rootFolderName);
      if(rootIndex === -1) {
        return;
      }
      const gIndex = this.indexes.findIndex((iIndex:number)=>{
        if(this.apis['apiInfoList'][iIndex]['name'] === rootFolderName){
          return true;
        }
      });

      if(gIndex === -1){
        return;
      }

      let dindex = this.grules[gIndex].findIndex((rule)=>{return rule.title === title;});

      if(dindex === -1){
        return;
      }
      
      
      let id = this.grules[gIndex][dindex].id;
      let rulesource =await this.getRuleSource(rootIndex,id);
      rulesource['source']=document.getText();
      delete rulesource['errors'];

      let response; 

      let result:sourceError[] =[];
      try{
        response = await axios.put(
          `${this.apis['apiInfoList'][rootIndex]['apiHostUrl']}/api/system/pipelines/rule/${id}`
          ,rulesource,
          {
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'X-Requested-By':this.apis['apiInfoList'][gIndex]['token']
            },
            auth: {
              username: this.apis['apiInfoList'][gIndex]['token'],
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

    public async getRuleSource(instanceIndex:number,id:string){
      try{
        const response = await axios.get(`${this.apis['apiInfoList'][instanceIndex]['apiHostUrl']}/api/system/pipelines/rule/${id}`, {
          headers: {
            'Accept': 'application/json'
          },
          auth: {
            username: this.apis['apiInfoList'][instanceIndex]['token'],
            password: this.accountPassword
          }
        });

        return response.data;
       }catch(e){
      }
    }
    public async logInfoCheck(url: string, token:string):Promise<boolean>{
      if(!(await this.testAPI(url))){
        return false;
      }      

      if(!await this.testUserInfo(url,token)){
        return false;
      }
      return true;
    }

    public  async testAPI(apiPath:string):Promise<boolean>{
        try{
            const res  = await axios.get(apiPath);
            if(res.status === 200){    return true; }
            else {return false;}
        }catch(e){
            return false;
        }
    }

    public async testUserInfo(apiPath:string, username:string):Promise<boolean>{
        try{
            let path="";
            if(apiPath.includes("/api")){
                path = apiPath.substring(0,apiPath.indexOf("/api"));
            }else{
             path = apiPath;}

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
                return true;
              }  

              return false;
        }catch(e){
            return false;
        }
    }

    public wrilteFile(rootIndex:number,rule:any){
      let paths = rule['title'].split(/[\\/]/);
      let cumulative = "";
      let name = this.apis['apiInfoList'][rootIndex]['name'];
      if(paths.length > 1){
        for(let i=0;i<paths.length -1 ; i++){
          this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${name}/${cumulative}${paths[i]}`));
          cumulative +=(paths[i] + "/");
        }
      }
      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${name}/${rule['title']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
    }
    
    public async prepareForwork(){
      this.indexes.forEach(async (num)=>{
        this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][num]['name']}`));
        if(await this.logInfoCheck(this.apis['apiInfoList'][num]['apiHostUrl'],this.apis['apiInfoList'][num]['token'])){
          let rules =await this.getAllRules(this.apis['apiInfoList'][num]['apiHostUrl'],this.apis['apiInfoList'][num]['token']);
          let tempArray:RuleField[]=[];
          rules.map((rule)=>{
            this.wrilteFile(num,rule);
            tempArray.push({  
              title: rule['title'],
              id: rule['id'],
              description: rule['description'],
            });
          });
  
          this.grules.push(tempArray);
        }else{
          vscode.window.showErrorMessage("API Info is not correct. Please check again...");
        }
      });
      
      this.graylogFilesystem.refresh();
    }

    public async getAllRules(url:string,token:string):Promise<[]>{
      try{
        const response = await axios.get(`${url}/api/system/pipelines/rule`, {
          headers: {
            'Accept': 'application/json'
          },
          auth: {
            username: token,
            password: this.accountPassword
          }
        });

        return response.data;
      }catch(e){
      }
      return [];
    }


    
    public async clearworkspace(result:{label:any,index:number}[]){
      this.indexes = [];
      result.forEach(element => {
        this.indexes.push(element.index);
      });

      vscode.workspace.saveAll().then(()=>{
        vscode.commands.executeCommand('workbench.action.closeAllEditors').then(async ()=>{
          for (const [name] of this.graylogFilesystem.readDirectory(vscode.Uri.parse('graylog:/'))) {
            this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${name}`));
          }
          await this.prepareForwork();
          this.graylogFilesystem.refresh();
        });
      });
    }

    
    public async refreshWorkspace(){
      this.indexes.forEach(async (indexNum,index)=>{
        let tempRules = await this.getAllRules(this.apis['apiInfoList'][indexNum]['apiHostUrl'],this.apis['apiInfoList'][indexNum]['token']);
        tempRules.forEach((tmpRule, tempIndex)=>{
          let fIdx = this.grules[index].findIndex((rule)=> rule['title'] === tmpRule['title']);
          if(fIdx > -1){
            this.updateRule(indexNum,this.grules[index][fIdx],tmpRule);
          }else{
            this.wrilteFile(indexNum,tmpRule);
          }
        });  
      });
  
    }

    public readRule(rootIndex:number,filePath: string){
      return this.graylogFilesystem.readFile(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][rootIndex]['name']}/${filePath}.grule`));
    }
    public updateRule(rootIndex:number,registeredRule:RuleField,updatedRule:any){
      let readdata="";
      if(updatedRule['source'] !== (readdata=this.readRule(rootIndex,registeredRule.title).toString())){
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][rootIndex]['name']}/${registeredRule['title']}.grule`), Buffer.from(updatedRule['source']), { create: true, overwrite: true });
      }
    }

    //#region read and write apiInfo to storage
    public async readSettingApiInfo(){
      const data= await this.secretStorage.get("graylogSetting");
      if(data){
        this.apiSettingInfo = data;
      }else{
        this.apiSettingInfo = JSON.stringify({"apiInfoList":[{"apiHostUrl":"","token":"","name":"Development"}]});
      }

      this.apis = JSON.parse(this.apiSettingInfo);
    }

    public async writeSettingApiInfoToStorage(apiInfo:string){
      await this.secretStorage.store("graylogSetting",apiInfo);
    }

    public writeSettingApiInfoToFileSystem(){
      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/graylogSetting.json`),Buffer.from(this.apiSettingInfo), { create: true, overwrite: true });
    }

    public async initSettings(){
      await this.readSettingApiInfo();
      this.writeSettingApiInfoToFileSystem();
    }

    public async openSettings(){
      const doc =await vscode.workspace.openTextDocument(vscode.Uri.parse(`graylog:/graylogSetting.json`));
      await vscode.window.showTextDocument(doc);
    }
    //#endregion

  }