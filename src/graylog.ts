import * as vscode from 'vscode';
import { GraylogFileSystemProvider, MyTreeItem } from './fileSystemProvider';
import { DecorationInstanceRenderOptions } from 'vscode';
import { replaceLinebreaks, truncateString,getPathSeparator } from './utils';
import { newFileSource, errorForeground, errorMessageBackground, errorBackgroundLight, errorForegroundLight, icon, InitGraylogSettingInfo} from './constants';
import { RuleField, sourceError, apiInstance, PipleLine, ServerInfo, Setting } from './interfaces';
import { API } from './api';
import { getFormatedHashValue } from './utils';
import * as moment from 'moment';

export class ConnectionPart{
    public apis: Setting;

    public accountPassword = "token";
    public workingDirectory = "";
    index: number = -1;
    public grules:RuleField[] = [];
    public errors:sourceError[] = [];
    public graylogSettings:any[] = [];

    public pipleLines:PipleLine[][] = [];
    public apiSettingInfo:string = "";
    
    api: API;
    pathSeparator = getPathSeparator();
    
    constructor( private graylogFilesystem: GraylogFileSystemProvider, private readonly secretStorage: vscode.SecretStorage){
      this.api = new API();
      this.apis = { serverList:[]};
    }

    
    public async createRule(filename:string){
      const firstSlashIndex = filename.indexOf(this.pathSeparator);
      const serverName = filename.substring(0,firstSlashIndex);
      const newRulename = filename.substring(firstSlashIndex+1);
      const rootIndex = this.apis.serverList.findIndex((element:apiInstance)=>{
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

      let  fileName = document.fileName;
      
      if(fileName[0] === this.pathSeparator) {
        fileName = fileName.substring(1);
      }
      const iIndex = fileName.indexOf(this.pathSeparator);

      fileName=fileName.substring(iIndex+1);
      
      let dIdx = fileName.lastIndexOf('.');
      let title= fileName.substring(0,dIdx);
      
      if( fileName.includes('.json') ){
        await vscode.commands.executeCommand('editor.action.formatDocument');

        if(fileName === 'graylogSetting.json'){ 
          let value;
          try {
            if(value = JSON.parse(document.getText())){
              this.apis.serverList = (value['graylogSettings']) as ServerInfo[];
              this.api.setApiInfo(this.apis);
  
              this.apiSettingInfo = document.getText();
              this.writeSettingApiInfoToStorage(this.apiSettingInfo);
             }
          } catch (error) {}
        }

        return;
      }
      
      const gIndex = this.index;
      const rootIndex = this.index;
      const dindex = this.grules.findIndex( ( rule )=>{ return rule.title === title; });

      if(dindex === -1){
        return;
      }
      
      
      this.setActiveStatusText( gIndex, this.grules[dindex].title);
      let id = this.grules[dindex].id;
      let rulesource =await this.api.getRuleSource( rootIndex, id );
      rulesource['source']=document.getText();
      delete rulesource['errors'];


      this.errors = await this.api.getErrorLines( rootIndex, id, rulesource);

      let ranges:vscode.Range[]=[];
      let decorationOptions:vscode.DecorationOptions[] = [];

      this.errors.forEach((oneresult)=>{
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
      const paths = rule['title'].split(/[\\/]/);
      let cumulative = vscode.Uri.parse('graylog:/');

      const name = this.apis.serverList[rootIndex]['name'];
      
      const basePath = vscode.Uri.parse('graylog:/');

      cumulative = vscode.Uri.joinPath( cumulative, name);

      if(paths.length > 1){
        for(let i=0;i<paths.length -1 ; i++){
          if(!this.graylogFilesystem.pathExists( vscode.Uri.joinPath( cumulative, paths[i] ) )){
            this.graylogFilesystem.createDirectory( vscode.Uri.joinPath( cumulative, paths[i] ) );
          }
          cumulative = vscode.Uri.joinPath( cumulative, paths[i] );
        }
      }

      this.graylogFilesystem.writeFile(  vscode.Uri.joinPath( cumulative, `${paths[paths.length -1]}.grule` ), Buffer.from(rule['source']), { create: true, overwrite: true });
    }
    
    public async prepareForwork(){
  
        const num = this.index;

        this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/${this.apis.serverList[num]['name']}`));
        if(await this.logInfoCheck(this.apis.serverList[num]['serverUrl'],this.apis.serverList[num]['token'])){
          const rules =await this.api.getAllRules(this.apis.serverList[num]['serverUrl'],this.apis.serverList[num]['token']);
          const tempArray:RuleField[]=[];
          rules.forEach((rule)=>{
            this.wrilteFile(num,rule);
            tempArray.push({  
              title: rule['title'],
              id: rule['id'],
              description: rule['description'],
            });
          });
  
          this.grules = tempArray;

          let pipelines =await this.api.getAllPipeLines(this.apis.serverList[num]['serverUrl'],this.apis.serverList[num]['token']);
          let tempPipelineArray:PipleLine[]=[];
          pipelines.forEach((pipeline : any)=>{
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
        
      this.graylogFilesystem.refresh();
    }

    


    
    public async clearworkspace(result:{label:any,index:number}){

      this.index = result.index;
      await vscode.workspace.saveAll();
      await vscode.commands.executeCommand('workbench.action.closeAllEditors');
      
      for (const [name] of this.graylogFilesystem.readDirectory(vscode.Uri.parse('graylog:/'))) {
          this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${name}`));
      }
      
      await this.prepareForwork();
      this.graylogFilesystem.refresh();
    }

    
    public async refreshWorkspace(){
      await vscode.workspace.saveAll();

      const indexNum = this.index;
      let tempRules = await this.api.getAllRules(this.apis.serverList[indexNum]['serverUrl'],this.apis.serverList[indexNum]['token']);
      for(const tmpRule of tempRules){
        let fIdx = this.grules.findIndex((rule)=> rule['title'] === tmpRule['title']);
        if(fIdx > -1){
          this.updateRule(indexNum,this.grules[fIdx],tmpRule);
        }else{
          this.grules.push(tmpRule);
          this.wrilteFile(indexNum,tmpRule);
        }
      }

      const updatedgRules:RuleField[]=[];
      for(const tmpgRule of this.grules){
        let fIdx = tempRules.findIndex((tmprule)=> tmpgRule['title'] === tmprule['title']);
        if(fIdx === -1){
          this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${this.apis.serverList[indexNum]['name']}/${tmpgRule['title']}.grule`));
        }else {
          updatedgRules.push(tmpgRule);
        }
      }
      this.grules = updatedgRules;


      let pipelines =await this.api.getAllPipeLines(this.apis.serverList[0]['serverUrl'],this.apis.serverList[0]['token']);
      let tempPipelineArray:PipleLine[]=[];
      pipelines.forEach((pipeline : any)=>{
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


      this.graylogFilesystem.refresh();
    }

    public readRule(rootIndex:number,filePath: string){
      const pathUri = this.generateUriFromTitle(rootIndex, filePath);

      return this.graylogFilesystem.readFile(pathUri);
    }

    generateUriFromTitle(rootIndex: number, title: string): vscode.Uri{
      const paths = title.split(/[\\/]/);

      let cumulative = vscode.Uri.parse('graylog:/');
      cumulative = vscode.Uri.joinPath( cumulative, this.apis.serverList[rootIndex]['name']);

      for(let i=0;i<paths.length -1 ; i++){
        cumulative = vscode.Uri.joinPath( cumulative, paths[i] );
      }

      cumulative = vscode.Uri.joinPath( cumulative, `${paths[paths.length-1]}.grule` );

      return cumulative;
    }

    public updateRule(rootIndex:number,registeredRule:RuleField,updatedRule:any){
      const path = this.generateUriFromTitle(rootIndex, registeredRule.title);
      
      if(updatedRule['source'] !== this.readRule(rootIndex,registeredRule.title).toString() ){
        this.graylogFilesystem.writeFile( path, Buffer.from(updatedRule['source']), { create: true, overwrite: true });
      }
    }

    //#region read and write apiInfo to storage
    public async readSettingApiInfo(){
      const data= await this.secretStorage.get("graylogSetting");
      if(data){
        this.apiSettingInfo = data;
      }else{
        this.apiSettingInfo = InitGraylogSettingInfo;
      }

      this.apis.serverList = JSON.parse(this.apiSettingInfo)['graylogSettings'];
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
      if(!this.apis.serverList){
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
      const rootIndex = this.apis.serverList.findIndex((info:any)=>info['name'] === rootFolderName);

      const data = await this.api.getFacilityAndServerVersion(rootIndex);
      const entities =[];
      for(const item of ids){
        const source=await this.api.getRuleSource(rootIndex,item);
        entities.push({
          "type": {
              "name": "pipeline_rule",
              "version": "1"
          },
          "v":"1",
          "id": getFormatedHashValue(`pipeline_rule;${this.apis.serverList[rootIndex].serverUrl};${Date.now.toString()};${source.source}`),
          "data": {
              "title": {
                  "@type": "string",
                  "@value": source.title
              },
              "description": {
                  "@type": "string",
                  "@value": source.description
              },
              "source": {
                  "@type": "string",
                  "@value": source.source
              }
          },
          "constraints": [
              {
                  "type": "server-version",
                  "version": ">=" + data?.version
              }
          ]
        });
      }

      const contentPackName = `Graylog Rules Manager Export - ${moment().format("YYYY-MM-DD HH:mm:ss")}`;
      const result = {
        "id": getFormatedHashValue(`content_pack;${this.apis.serverList[rootIndex].serverUrl};${moment().format("YYYY-MM-DD HH:mm:ss")};${this.apis.serverList[rootIndex].token}`),
        "rev": 1,
        "v": "1",
        "name": contentPackName,
        "summary": "Graylog Rules Content Pack",
        "description": "Content Pack of Graylog Rules",
        "vendor": "Graylog Rules Manager",
        "url": "https://www.graylog.org/post/introducing-graylog-labs/",
        "server_version": data?.version,
        "parameters": [],
        entities
      };

      
      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/contentPack.json`), Buffer.from( JSON.stringify(result) ), { create: true, overwrite: true });
      vscode.commands.executeCommand( 'vscode.open', vscode.Uri.parse(`graylog:/contentPack.json`));
      
    }

    getRuleId(uri:vscode.Uri):string | undefined{
      let title = uri.path.substring(1);;
      let rootFolderName = uri.path.split(/[\\|/]/)[1];
      
      
      title = title.replace(rootFolderName,"").substring(1).replace(/[\\|/]/,'/').replace(".grule","");

      for(const item of this.grules){
        if(item.title === title){
          return item.id;
        }
      }
      return undefined;
    }
    //#endregion

    //#region

    async saveActiveEditorContent(){
      const uri = await vscode.window.showSaveDialog({
        saveLabel: "Save ContentPack",
        title: "Save ContentPack",
        filters: {
          'All files': ['*']
        }
      });

      if(uri && vscode.window.activeTextEditor?.document.uri) {
        vscode.workspace.fs.writeFile( uri, this.graylogFilesystem.readFile( vscode.window.activeTextEditor?.document.uri));
      }
    }

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
      const rootIndex = this.apis.serverList.findIndex((info:any)=>info['name'] === rootFolderName);
      this.api.createRule(rootIndex,value);
      vscode.commands.executeCommand("graylog.RefreshWorkSpace");
    }
    //#endregion

    //#regin status bar
    setActiveStatusText( rootIndex: number, title: string){
      let tmpPipelines:string[] = [];
      this.pipleLines[rootIndex].forEach(pipleline =>{
        if(pipleline.usedInRules.includes(title)){
          tmpPipelines.push(pipleline.title);
        }
      });

      vscode.commands.executeCommand('graylog.setStatusBar',`Used in pipelines: ${tmpPipelines.join(',')}`);
    }
    //#endregion
  }