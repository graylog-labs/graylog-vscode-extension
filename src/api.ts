import axios from 'axios';
import { newFileSource } from './constants';
import { sourceError } from './interfaces';
import { MyTreeItem } from './fileSystemProvider';
import { getFormatedHashValue } from './utils';
import * as moment from 'moment';
export class API{

    accountPassword = "token";
    apis:any;
    setApiInfo(info:any){
        this.apis = info;
    }

    async testUserInfo(apiPath:string, username:string):Promise<boolean>{
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

    async testAPI(apiPath:string):Promise<boolean>{
        try{
            const res  = await axios.get(apiPath);
            if(res.status === 200){    return true; }
            else {return false;}
        }catch(e){
            return false;
        }
    }
    
    async getRuleSource(instanceIndex:number,id:string){
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
    
    public async getErrorLines(rootIndex: number, id:string, rulesource: string):Promise<sourceError[]>{
      const result:sourceError[] =[];
      try{
        await axios.put(
          `${this.apis['apiInfoList'][rootIndex]['apiHostUrl']}/api/system/pipelines/rule/${id}`
          ,rulesource,
          {
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'X-Requested-By':this.apis['apiInfoList'][rootIndex]['token']
            },
            auth: {
              username: this.apis['apiInfoList'][rootIndex]['token'],
              password: this.accountPassword
            }
          }
        );
      }catch(e){
        if(e.response?.data && Array.isArray(e.response?.data)){
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
      return result;
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

    async getFacilityAndServerVersion(rootIndex:number):Promise<{facility:string,version:string} | undefined>{

      try{
        const response = await axios.get(`${this.apis['apiInfoList'][rootIndex].apiHostUrl}/api/system`, {
          headers: {
            'Accept': 'application/json'
          },
          auth: {
            username: this.apis['apiInfoList'][rootIndex].token,
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
      
        const response = await axios.post(`${this.apis['apiInfoList'][rootIndex].apiHostUrl}/api/system/content_packs/generate_id`, {},{
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Requested-By':this.apis['apiInfoList'][rootIndex].token
          },
          auth: {
            username: this.apis['apiInfoList'][rootIndex].token,
            password: "token"
          }
        });

        return response.data;
    }

    async createRule(rootIndex:number, title: string ):Promise<any>{
        const response = await axios.post(
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
            return response.data;
          }
        return null;
    }
//,


    async createContentPack(rootIndex:number,items:string[]){
      const apiUrl =`${this.apis['apiInfoList'][rootIndex].apiHostUrl}/api/system/content_packs`;
      const data = await this.getFacilityAndServerVersion(rootIndex);
      let hashString = `${this.apis['apiInfoList'][rootIndex].apiHostUrl} count=${items.length} `;
      hashString += items.join("");
      
      const entities =[];
      for(const item of items){
        const source=await this.getRuleSource(rootIndex,item);
        entities.push({
          "type": {
              "name": "pipeline_rule",
              "version": "1"
          },
          "v":"1",
          "id": getFormatedHashValue(`pipeline_rule;${this.apis['apiInfoList'][rootIndex].apiHostUrl};${Date.now.toString()};${source.source}`),
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
      let response="";
      try {
        response = await axios.post(
          apiUrl
          ,
          {
            "id": getFormatedHashValue(`content_pack;${this.apis['apiInfoList'][rootIndex].apiHostUrl};${moment().format("YYYY-MM-DD HH:mm:ss")};${this.apis['apiInfoList'][rootIndex].token}`),
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
          }
          ,
          {
            headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json',
              'X-Requested-By':this.apis['apiInfoList'][rootIndex].token
            },
            auth: {
              username: this.apis['apiInfoList'][rootIndex].token,
              password: "token"
            }
          }
        );
      } catch (error) {
        
      }
      
    }



  public async getAllPipeLines(url:string,token:string):Promise<[]>{
      try{
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