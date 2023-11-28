import axios, { GenericAbortSignal } from 'axios';
import { newFileSource } from './constants';
import { sourceError, ServerInfo, Setting } from './interfaces';
import { MyTreeItem } from './fileSystemProvider';
import { getFormatedHashValue } from './utils';
import { crtPath, serverKey } from './constants';
import * as vscode from 'vscode';

import { promises as fs } from 'fs';

export class API{

  key: any;

  extensionPath: vscode.Uri;

  constructor(path: vscode.Uri){
    this.extensionPath = path;
  }

    accountPassword = "token";
    apis: Setting = { serverList:[] };
    setApiInfo( info:Setting ){
        this.apis = info;
    }

    async testUserInfo(apiPath:string, username:string):Promise<boolean>{
        try{
            let path="";
            if(apiPath.includes("/api")){
                path = apiPath.substring(0,apiPath.indexOf("/api"));
            }else{
             path = apiPath;}
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
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

            // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    async testAPI(apiPath:string):Promise<boolean>{
      let res;
        try{
           process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
            res  = await axios.get(apiPath);
            if(res.status === 200){    return true; }
            else {return false;}
        }catch(e){
            return false;
        }
    }

    async testPattern(url: string, token: string, body: Record<string, string | Record<string, string>>, signal: GenericAbortSignal):Promise<Record<string, string>>{
        try{
          process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
          const response = await axios.post(`${url}/api/system/grok/test`, body, {
            headers: {
              'Content-Type': 'application/json',
              'x-requested-by': 'XMLHttpRequest'
            },
            auth: {
              username: token,
              password: this.accountPassword
            },
            signal,
          });
          return {...response.data, success: true};
        }catch(e){
          if(e.response?.data?.message){
            throw new Error(e.response.data.message);
          } else {
            console.log({e});
          }
        }
        return {};
    }

    async getRuleSource(instanceIndex:number,id:string){
        try{
         process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
          const response = await axios.get(`${this.apis.serverList[instanceIndex]['serverUrl']}/api/system/pipelines/rule/${id}`, {
            headers: {
              'Accept': 'application/json'
            },
            auth: {
              username: this.apis.serverList[instanceIndex]['token'],
              password: this.accountPassword
            }
          });

          return response.data;
         }catch(e){
        }
      }

    public async getErrorLines(rootIndex: number, id:string, rulesource: string):Promise<sourceError[]>{
      const result:sourceError[] =[];
      try{
       process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        await axios.put(
          `${this.apis.serverList[rootIndex]['serverUrl']}/api/system/pipelines/rule/${id}`
          ,rulesource,
          {
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'X-Requested-By':this.apis.serverList[rootIndex]['token']
            },
            auth: {
              username: this.apis.serverList[rootIndex]['token'],
              password: this.accountPassword
            }
          }
        );
      }catch(e){
        if(e.response?.data && Array.isArray(e.response?.data)){
          e.response.data.forEach((edata:any)=>{
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
      return result;
    }


    public async getAllRules(url:string,token:string):Promise<[]>{
        try{
         process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
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

    async getFacilityAndServerVersion(rootIndex:number):Promise<{facility:string,version:string} | undefined>{

      try{
       process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        const response = await axios.get(`${this.apis.serverList[rootIndex].serverUrl}/api/system`, {
          headers: {
            'Accept': 'application/json'
          },
          auth: {
            username: this.apis.serverList[rootIndex].token,
            password: this.accountPassword
          }
        });

        return {
          facility:response.data["facility"],
          version: response.data["version"]
        };
      }catch(e){
      }

      return undefined;

    }
    async getRuleConstraint(rootIndex:number,id: string){
     process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        const response = await axios.post(`${this.apis.serverList[rootIndex].serverUrl}/api/system/content_packs/generate_id`, {},{
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Requested-By':this.apis.serverList[rootIndex].token
          },
          auth: {
            username: this.apis.serverList[rootIndex].token,
            password: "token"
          }
        });

        return response.data;
    }

    async createRule(rootIndex:number, title: string ):Promise<any>{
     process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        const response = await axios.post(
            `${this.apis.serverList[rootIndex].serverUrl}/api/system/pipelines/rule`
            ,{
              title: title,
              source:newFileSource(title),
              description: title
            },
            {
              headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-By':this.apis.serverList[rootIndex].token
              },
              auth: {
                username: this.apis.serverList[rootIndex].token,
                password: this.accountPassword
              }
            }
          );
          if(response.status === 200){
            return response.data;
          }
        return null;
    }


  public async getAllPipeLines(url:string,token:string):Promise<[]>{
      try{
       process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        const response = await axios.get(`${url}/api/system/pipelines/pipeline`, {
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
}