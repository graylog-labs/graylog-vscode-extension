import * as vscode from 'vscode';
import { GraylogFileSystemProvider, MyTreeItem } from './fileSystemProvider';
import { DecorationInstanceRenderOptions } from 'vscode';
import { replaceLinebreaks, truncateString,getPathSeparator } from './utils';
import { newFileSource, errorForeground, errorMessageBackground, errorBackgroundLight, errorForegroundLight, icon} from './constants';
import {RuleField, sourceError, apiInstance, PipleLine} from './interfaces';
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
    public graylogSettings:any[] = [];

    public pipleLines:PipleLine[][] = [];
    public apiSettingInfo:string = "";
    
    api:API;
    pathSeparator=getPathSeparator();
    
    // createEditItem:MyTreeItem = null;
    constructor(private graylogFilesystem: GraylogFileSystemProvider,private readonly secretStorage:vscode.SecretStorage){
      this.api = new API();
    }

    
    public async createRule(filename:string){
      const firstSlashIndex = filename.indexOf(this.pathSeparator);
      const serverName = filename.substring(0,firstSlashIndex);
      const newRulename = filename.substring(firstSlashIndex+1);
      const rootIndex = this.apis['graylogSettings'].findIndex((element:apiInstance)=>{
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
    }
    
    public async onDidChange(document:vscode.TextDocument){
      await this.chekcInfo();

//      let lIdx = document.fileName.lastIndexOf(this.pathSeparator);
      let  fileName = document.fileName;
      
      if(fileName[0] === this.pathSeparator) {
        fileName = fileName.substring(1);
      }
      const iIndex = fileName.indexOf(this.pathSeparator);

      fileName=fileName.substring(iIndex+1);
      
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
      let rootIndex = this.apis["graylogSettings"].findIndex((info:any)=>info['name'] === rootFolderName);
      if(rootIndex === -1) {
        return;
      }
      const gIndex = this.indexes.findIndex((iIndex:number)=>{
        if(this.apis['graylogSettings'][iIndex]['name'] === rootFolderName){
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
      
      
      this.setActiveStatusText( gIndex, this.grules[gIndex][dindex].title);
      let id = this.grules[gIndex][dindex].id;
      let rulesource =await this.api.getRuleSource( rootIndex, id );
      rulesource['source']=document.getText();
      delete rulesource['errors'];


      this.errors = await this.api.getErrorLines( rootIndex, id, rulesource);

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
      let name = this.apis['graylogSettings'][rootIndex]['name'];
      if(paths.length > 1){
        for(let i=0;i<paths.length -1 ; i++){
          if(!this.graylogFilesystem.pathExists(vscode.Uri.parse(`graylog:/${name}/${cumulative}${paths[i]}`))){
            this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${name}/${cumulative}${paths[i]}`));
          }

          cumulative +=(paths[i] + "/");
        }
      }
      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${name}/${rule['title']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
    }
    
    public async prepareForwork(){
      this.indexes.forEach(async (num)=>{
        this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${this.apis['graylogSettings'][num]['name']}`));
        if(await this.logInfoCheck(this.apis['graylogSettings'][num]['serverUrl'],this.apis['graylogSettings'][num]['token'])){
          let rules =await this.api.getAllRules(this.apis['graylogSettings'][num]['serverUrl'],this.apis['graylogSettings'][num]['token']);
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

          let pipelines =await this.api.getAllPipeLines(this.apis['graylogSettings'][num]['serverUrl'],this.apis['graylogSettings'][num]['token']);
          let tempPipelineArray:PipleLine[]=[];
          pipelines.map((pipeline : any)=>{
            const usedin:string[] = [];
            pipeline['stages'].forEach(( stage: any )=>{
              stage['rules'].forEach( (ruleName:string) => {
                if(!usedin.includes(ruleName)){
                  usedin.push(ruleName);
                }
              });
            });
            tempPipelineArray.push({  
              id: pipeline['id'],
              title: pipeline['title'],
              description: pipeline['description'],
              source: pipeline['source'],
              stages: pipeline['stages'],
              errors: pipeline['errors'],
              usedInRules: usedin
            });
          });
  
          this.pipleLines.push(tempPipelineArray);

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

    
    public refreshWorkspace(){
      vscode.workspace.saveAll().then(async ()=>{
        for(let index=0;index<this.indexes.length;index++){
          const indexNum = this.indexes[index];
          let tempRules = await this.api.getAllRules(this.apis['graylogSettings'][indexNum]['serverUrl'],this.apis['graylogSettings'][indexNum]['token']);
          for(const tmpRule of tempRules){
            let fIdx = this.grules[index].findIndex((rule)=> rule['title'] === tmpRule['title']);
            if(fIdx > -1){
              this.updateRule(indexNum,this.grules[index][fIdx],tmpRule);
            }else{
              this.grules[index].push(tmpRule);
              this.wrilteFile(indexNum,tmpRule);
            }
          }
  
          const updatedgRules:RuleField[]=[];
          for(const tmpgRule of this.grules[index]){
            let fIdx = tempRules.findIndex((tmprule)=> tmpgRule['title'] === tmprule['title']);
            if(fIdx === -1){
              this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${this.apis['graylogSettings'][indexNum]['name']}/${tmpgRule['title']}.grule`));
            }else {
              updatedgRules.push(tmpgRule);
            }
          }
          this.grules[index] = updatedgRules;


          let pipelines =await this.api.getAllPipeLines(this.apis['graylogSettings'][index]['serverUrl'],this.apis['graylogSettings'][index]['token']);
          let tempPipelineArray:PipleLine[]=[];
          pipelines.map((pipeline : any)=>{
            const usedin:string[] = [];
            pipeline['stages'].forEach(( stage: any )=>{
              stage['rules'].forEach( (ruleName:string) => {
                if(!usedin.includes(ruleName)){
                  usedin.push(ruleName);
                }
              });
            });
            tempPipelineArray.push({  
              id: pipeline['id'],
              title: pipeline['title'],
              description: pipeline['description'],
              source: pipeline['source'],
              stages: pipeline['stages'],
              errors: pipeline['errors'],
              usedInRules: usedin
            });
          });
  
          this.pipleLines.push(tempPipelineArray);
        }
  
        this.graylogFilesystem.refresh();
      });  
    }

    public readRule(rootIndex:number,filePath: string){
      return this.graylogFilesystem.readFile(vscode.Uri.parse(`graylog:/${this.apis['graylogSettings'][rootIndex]['name']}/${filePath}.grule`));
    }
    public updateRule(rootIndex:number,registeredRule:RuleField,updatedRule:any){
      let readdata="";
      if(updatedRule['source'] !== (readdata=this.readRule(rootIndex,registeredRule.title).toString())){
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${this.apis['graylogSettings'][rootIndex]['name']}/${registeredRule['title']}.grule`), Buffer.from(updatedRule['source']), { create: true, overwrite: true });
      }
    }

    //#region read and write apiInfo to storage
    public async readSettingApiInfo(){
      const data= await this.secretStorage.get("graylogSetting");
      if(data){
        this.apiSettingInfo = data;
      }else{
        this.apiSettingInfo = JSON.stringify({"graylogSettings":[{"serverUrl":"","token":"","name":"Development"}]});
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

    async chekcInfo(){
      if(!this.apis['graylogSettings']){
        await this.readSettingApiInfo();
      }
    }
    //#endregion


    //#region createContentPacktype:"pipeline_rule",
                // id
    async createContentPack(){
      const items:MyTreeItem[]=this.graylogFilesystem.selected;

      const ids:string[]=[];
      if(items.length>0){
        items.forEach((rule)=>{
            const id =this.getRuleId(rule.pathUri);
            if(id){
              ids.push(id);
            }  
        });
      }
      
      let rootFolderName = items[0].pathUri.path.split(/[\\|/]/)[1];
      const rootIndex = this.apis["graylogSettings"].findIndex((info:any)=>info['name'] === rootFolderName);
      await this.api.createContentPack(rootIndex,ids);
      // await this.api.createContentPack(rootIndex);
    }

    getRuleId(uri:vscode.Uri):string | undefined{
      let title = uri.path.substring(1);;
      let rootFolderName = uri.path.split(/[\\|/]/)[1];
      
      
      title = title.replace(rootFolderName,"").substring(1).replace(/[\\|/]/,'/').replace(".grule","");
      const rootIndex = this.apis["graylogSettings"].findIndex((info:any)=>info['name'] === rootFolderName);

      const gIndex = this.indexes.findIndex((iIndex:number)=>{
        if(this.apis['graylogSettings'][iIndex]['name'] === rootFolderName){
          return true;
        }
      });

      for(const item of this.grules[gIndex]){
        if(item.title === title){
          return item.id;
        }
      }
      return undefined;
    }
    //#endregion

    //#region
    async saveToLocalFolder(item:MyTreeItem){
      const uri = await vscode.window.showOpenDialog({
        canSelectFolders: true,
        canSelectFiles: false,
        canSelectMany: false,
        openLabel:'Select Folder'
      });

      if (uri) {
        this.saveFilrOrFolder(item,uri[0]);
      }
    }
    
    async saveFilrOrFolder(item:MyTreeItem, fileUri:vscode.Uri){
      if(this.graylogFilesystem.hasChildren(item)){
        vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(fileUri,...this.getFileOrFolderPath(item.pathUri)));
        const items=await this.graylogFilesystem.getChildren(item);
        for(const treeItem of items){
          await this.saveFilrOrFolder(treeItem,fileUri);
        }
      }else{
        vscode.workspace.fs.writeFile(vscode.Uri.joinPath(fileUri,...this.getFileOrFolderPath(item.pathUri)),this.graylogFilesystem.readFile(item.pathUri));
      }
    }

    getFileOrFolderPath(uri:vscode.Uri):string[]{
      let fpath = uri.path;
      if(fpath[0] === '\\' || fpath[0]==='/'){
        fpath = fpath.substring(1);
      }
      const paths = fpath.split(/[\\|/]/); 
      return paths;
    }


    async createNewRule(item: MyTreeItem, value :string){
      let rootFolderName = item.pathUri.path.split(/[\\|/]/)[1];
      const rootIndex = this.apis["graylogSettings"].findIndex((info:any)=>info['name'] === rootFolderName);
      this.api.createRule(rootIndex,value);
      vscode.commands.executeCommand("graylog.RereshWorkSpace");
    }
    //#endregion

    //#regin status bar
    setActiveStatusText( rootIndex: number, title: string){
      let tmpPipelines:string[] = [];
      this.pipleLines[rootIndex].map(pipleline =>{
        if(pipleline.usedInRules.includes(title)){
          tmpPipelines.push(pipleline.title);
        }
      });

      vscode.commands.executeCommand('graylog.setStatusBar',`Used in pipelines: ${tmpPipelines.join(',')}`);
    }
    //#endregion
  }