import * as vscode from 'vscode';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import { DecorationInstanceRenderOptions } from 'vscode';
import { replaceLinebreaks, truncateString,getPathSeparator } from './utils';
import { newFileSource, errorForeground, errorMessageBackground, errorBackgroundLight, errorForegroundLight, icon} from './constants';
import {RuleField, sourceError, apiInstance} from './interfaces';
import { API } from './api';


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
    
    api:API;
    pathSeparator=getPathSeparator();
    
    constructor(private graylogFilesystem: GraylogFileSystemProvider,private readonly secretStorage:vscode.SecretStorage){
      this.api = new API();
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
      try {
        const data = await this.api.createRule(rootIndex,title);   
        if(data !== null){
          this.wrilteFile(rootIndex, data);
        }     
      } catch (error) {
          vscode.window.showErrorMessage(error);
          this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${filename}.grule`));     
          return;
      }
      
        // response = await axios.post(
        //   `${this.apis['apiInfoList'][rootIndex].apiHostUrl}/api/system/pipelines/rule`
        //   ,{
        //     title: title,
        //     source:newFileSource(title),
        //     description: title
        //   },
        //   {
        //     headers: {
        //       Accept: 'application/json',
        //       'Content-Type': 'application/json',
        //       'X-Requested-By':this.apis['apiInfoList'][rootIndex].token
        //     },
        //     auth: {
        //       username: this.apis['apiInfoList'][rootIndex].token,
        //       password: this.accountPassword
        //     }
        //   }
        // );

      //   if(response.status === 200){
      //     this.wrilteFile(rootIndex,response.data);
      //   }
      // }catch(e){
       
      // }
    }
    
    public async onDidChange(document:vscode.TextDocument){
      let lIdx = document.fileName.lastIndexOf(this.pathSeparator);
      let  fileName = document.fileName.substring(lIdx+1);
      if(fileName[0] === this.pathSeparator) {
        fileName = fileName.substring(1);
      }
      let dIdx = fileName.lastIndexOf('.');
      let title= fileName.substring(0,dIdx);
      
      if(fileName === 'graylogSetting.json'){
         let value="";
         try {
          if(value = JSON.parse(document.getText())){
            this.apis = value;
            this.api.setApiInfo(value);

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
      let rulesource =await this.api.getRuleSource(rootIndex,id);
      rulesource['source']=document.getText();
      delete rulesource['errors'];


      this.errors = await this.api.getErrorLines(rootIndex,id,rulesource);

      let ranges:vscode.Range[]=[];
      let decorationOptions:vscode.DecorationOptions[] = [];

      this.errors.map((oneresult)=>{
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

    public async logInfoCheck(url: string, token:string):Promise<boolean>{
      if(!(await this.api.testAPI(url))){
        return false;
      }      

      if(!await this.api.testUserInfo(url,token)){
        return false;
      }
      return true;
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
          let rules =await this.api.getAllRules(this.apis['apiInfoList'][num]['apiHostUrl'],this.apis['apiInfoList'][num]['token']);
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
        let tempRules = await this.apis.getAllRules(this.apis['apiInfoList'][indexNum]['apiHostUrl'],this.apis['apiInfoList'][indexNum]['token']);
        tempRules.forEach((tmpRule:any, tempIndex:number)=>{
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
      this.api.setApiInfo(this.apis);
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