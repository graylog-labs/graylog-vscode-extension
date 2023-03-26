import * as vscode from 'vscode';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import axios from 'axios';
import { DecorationInstanceRenderOptions,ThemeColor } from 'vscode';
import { replaceLinebreaks, truncateString } from './utils';
import { newFileSource } from './constants';
const BASE_PATH = `${vscode?.extensions?.getExtension('pdragon.task-graylog')?.extensionPath}/resources/`;
const ICON_PATH='error-inverse.svg';
const errorForeground = new ThemeColor('graylog.errorForeground');
const errorForegroundLight = new ThemeColor('graylog.errorForegroundLight');
const errorMessageBackground: ThemeColor | undefined = new ThemeColor('graylog.errorMessageBackground');
const errorBackground: ThemeColor | undefined = new ThemeColor('graylog.errorBackground');
const errorBackgroundLight: ThemeColor | undefined = new ThemeColor('graylog.errorBackgroundLight');

const icon = vscode.window.createTextEditorDecorationType({
  gutterIconPath:`${BASE_PATH}${ICON_PATH}`,
  gutterIconSize:'80%',
  isWholeLine: true,
  backgroundColor: errorBackground
});


export class ConnectionPart{


    public apiUrl:string = "";
    public token = "";
    public accountPassword = "token";
    public workingDirectory="";
    public grules:RuleField[] =[];
    public errors:sourceError[]=[];
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
      let title= document.fileName.replace('/','').split('.')[0];
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
      this.grules.push({  
        title: rule['title'],
        id: rule['id'],
        description: rule['description']
      });
      this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${rule['title']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
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
          // var directory = this.graylogFilesystem.readDirectory(vscode.Uri.parse('graylog:/'));
          // directory.map((eachfile)=>{
          //   this.graylogFilesystem.delete(vscode.Uri.parse(`graylog:/${eachfile}`))
          // });
          vscode.workspace.updateWorkspaceFolders(index,1);
        }
      });

      if(await this.secretStorage.get("reloaded") != "yes"){
        this.LoginInitialize();
      }
    }
}

export interface RuleField{
  title: string,
  description: string,
  id: string,
}

export interface sourceError{
  line: number,
  position_in_line: number,
  reason: string,
  type: string
}
