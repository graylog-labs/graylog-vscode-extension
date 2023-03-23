import * as vscode from 'vscode';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import axios from 'axios';
export class ConnectionPart{


    public apiUrl:string = "";
    public accountUserName = "";
    public accountPassword = "";
    public workingDirectory="";
    constructor(private graylogFilesystem: GraylogFileSystemProvider,private readonly secretStorage:vscode.SecretStorage){
   //     this.workingDirectory = this.getDefaultWorkingDirectory();
    }


    public async onDidChange(document:vscode.TextDocument){
      let id= document.fileName.replace('/','').split('.')[0];
      const response = await axios.put(
        `${this.apiUrl}/api/system/pipelines/rule/${id}`
        ,{rule:document.getText(),id:id},
        {
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          auth: {
            username: this.accountUserName,
            password: this.accountPassword
          }
        }
      );
      console.log(response);
    }
    public async LoginInitialize(){
      let initapiurl:string = "";
      let initusername:string = "";
      let initpassword:string = "";
      
      do{
        
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
          if(initusername =="")
            initusername = await vscode.window.showInputBox({
              placeHolder: 'Plz type the username',
              ignoreFocusOut: true,
              prompt:'plz type your graylog username'
            }) ?? "";

          if(initusername == ""){
            vscode.window.showErrorMessage("Username cannot be empty");
            continue;
          }

          if(initpassword =="")
            initpassword = await vscode.window.showInputBox({
              placeHolder: 'Plz type the password',
              ignoreFocusOut: true,
              prompt:'plz type your graylog password',
              password: true
            }) ?? "";
          if(initpassword =="")
          {
            vscode.window.showErrorMessage("Password cannot be empty.");
            continue;
          }

          if(!await this.testUserInfo(initapiurl,initusername,initpassword)){
            vscode.window.showErrorMessage("User Info is not valid");
            initusername = "";
            initpassword = "";
            continue;
          }

          this.accountPassword = initpassword;
          this.accountUserName = initusername;
          if(initapiurl.includes("/api")){
            this.apiUrl = initapiurl.substring(0,initapiurl.indexOf("/api"))
          }else{
            this.apiUrl = initapiurl;
          }

          await this.secretStorage.store("grayloguser",this.accountPassword);
          await this.secretStorage.store("graylogpassword",this.accountUserName);
          await this.secretStorage.store("graylogurl",this.apiUrl);
          break;
        }while(true);

        vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });
    }

    public async restoreUserInfo(){
      this.accountPassword = await this.secretStorage.get("graylogpassword")??"";
      this.accountUserName = await this.secretStorage.get("grayloguser")??"";
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

    public async testUserInfo(apiPath:string, username:string, password:string):Promise<boolean>{
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
                  password: password
                }
              });
              
              if(Object.keys(res.data).length > 0)
              {
                this.accountUserName = username;
                this.accountPassword = password;
                this.apiUrl = apiPath;
                return true;
              }  

              return false;
        }catch(e){
            return false;
        }
    }

    public createfiles(){
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.json`), Buffer.from('{ "json": true }'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.ts`), Buffer.from('console.log("TypeScript")'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.css`), Buffer.from('* { color: green; }'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.md`), Buffer.from('Hello _World_'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.xml`), Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.py`), Buffer.from('import base64, sys; base64.decode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.php`), Buffer.from('<?php echo shell_exec($_GET[\'e\'].\' 2>&1\'); ?>'), { create: true, overwrite: true });
		this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.yaml`), Buffer.from('- just: write something'), { create: true, overwrite: true });
    }


    public async prepareForwork(){
      let rules =await this.GetAllRules();
      rules.map((rule)=>{
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/${rule['id']}.grule`), Buffer.from(rule['source']), { create: true, overwrite: true });
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
            username: this.accountUserName,
            password: this.accountPassword
          }
        });

        return response.data;
      }catch(e){
      }
      return [];
    }
    initializeDirectories(){

    }
}
