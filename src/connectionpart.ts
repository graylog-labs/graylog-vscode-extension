import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { GraylogFileSystemProvider } from './fileSystemProvider';

export class ConnectionPart{
    public workingDirectory="";
    constructor(private graylogFilesystem: GraylogFileSystemProvider){
        this.workingDirectory = this.getDefaultWorkingDirectory();
    }

    getDefaultWorkingDirectory():string{
        
        if(fs.existsSync("C:\\")){
            if(!fs.existsSync("C:\\"))
            {
                fs.mkdirSync("C:\\.gray_log");
            }
            return "C:\\.gray_log";
        }

        if(fs.existsSync("/bin")){
            this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/.garylog/`));
            this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/.garylog/setting.json`));
            this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/.garylog/setting.json`), 
            Buffer.from(`{
                username:'',
                password:'',
            }`), { create: true, overwrite: true });
            
            return "graylog://.graylog";
        }
        return "";
    }
}
