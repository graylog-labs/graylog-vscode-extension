import * as vscode from 'vscode';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import axios from 'axios';
import { DecorationInstanceRenderOptions } from 'vscode';
import { replaceLinebreaks, truncateString } from './utils';
import { newFileSource, errorForeground, errorMessageBackground, errorBackgroundLight, errorForegroundLight, icon} from './constants';
import {RuleField, sourceError, apiInstance} from './interfaces';



export class ConnectionPart{
  ////multi
    public apis:any;
  ///

    public accountPassword = "token";
    public workingDirectory="";
    public indexString: string | undefined ="";
    indexes:number[]=[];
    public grules:RuleField[][] =[];
    public errors:sourceError[]=[];
    public apiInfoList:any[] = [];

    public apiSettingInfo:string = "";
    
    constructor(private graylogFilesystem: GraylogFileSystemProvider,private readonly secretStorage:vscode.SecretStorage){
    }


    public async createRule(filename:string){
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
    public async onDidChange(document:vscode.TextDocument){
      let lIdx = document.fileName.lastIndexOf('/');
      let  fileName = document.fileName.substring(lIdx+1);
      let dIdx = fileName.lastIndexOf('.');
      let title= fileName.substring(0,dIdx);
      
      if(fileName == `graylogSetting.json`){
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
      const rootFolderName = document.fileName.split('/')[1];
      let rootIndex = this.apis["apiInfoList"].findIndex((info:any)=>info['name']==rootFolderName);
      if(rootIndex==-1) return;

      const gIndex = this.indexes.findIndex((iIndex:number)=>{
        if(this.apis['apiInfoList'][iIndex]['name'] == rootFolderName)
          return true;
      });

      if(gIndex == -1)
        return;

      let dindex = this.grules[gIndex].findIndex((rule)=>{return rule.title == title});

      if(dindex == -1)
        return;
      
      
      let id = this.grules[gIndex][dindex].id;
      let rulesource =await this.GetRuleSource(rootIndex,id);
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

    public async GetRuleSource(instanceIndex:number,id:string){
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
    public async LogInfoCheck(url: string, token:string):Promise<boolean>{
      // let initapiurl:string = "";
      // let inittoken:string = "";
      if(!(await this.testAPI(url))){
        return false;
      }      

      if(!await this.testUserInfo(url,token)){
        return false;
      }
      return true;
    }

    // public async restoreUserInfo(){
    //   this.token = await this.secretStorage.get("graylogtoken")??"";
    //   this.apiUrl = await this.secretStorage.get("graylogurl")??"";
    // }
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
                return true;
              }  

              return false;
        }catch(e){
            return false;
        }
    }

    public wrilteFile(rootIndex:number,rule:any){
      

      let paths = rule['title'].split('/');
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
      this.indexString = await this.secretStorage.get("indexes");

      if(!this.indexString) return;
      const indexs:number[]=[];

      this.indexString.split(',').forEach(data=>{
        indexs.push(parseInt(data));
      });

      this.indexes = indexs;
      indexs.forEach(async (num)=>{
        this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][num]['name']}`));
        if(await this.LogInfoCheck(this.apis['apiInfoList'][num]['apiHostUrl'],this.apis['apiInfoList'][num]['token'])){
          let rules =await this.GetAllRules(this.apis['apiInfoList'][num]['apiHostUrl'],this.apis['apiInfoList'][num]['token']);
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
        }
      });
    }

    public async GetAllRules(url:string,token:string):Promise<[]>{
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
      this.indexString="";
      const workSpaceFoldersToAdd:{ uri:vscode.Uri, name:string}[]=[];
      
      result.forEach(element => {
        if(this.indexString!=undefined && this.indexString!=null){
          if(this.indexString.length>0)
            this.indexString+=",";
          this.indexString+=element.index;
          workSpaceFoldersToAdd.push({
            uri:vscode.Uri.parse(`graylog:/${this.apis['apiInfoList'][element.index]['name']}`),
            name:this.apis['apiInfoList'][element.index]['name']
          })
        }
      });
      
      await this.secretStorage.store("indexes",this.indexString); // when vs code reloaded, restore the checked instances from this string
      await this.secretStorage.store("reloaded","no");

      let removeCount=0;
      vscode.workspace.workspaceFolders?.map(async (folder, index)=>{
        if(folder.uri.toString().includes('graylog:/')){
          removeCount++;
        }
      });
      vscode.workspace.updateWorkspaceFolders(0, removeCount, ...workSpaceFoldersToAdd);
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