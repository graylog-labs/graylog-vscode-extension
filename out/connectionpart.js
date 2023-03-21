"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectionPart = void 0;
const vscode = require("vscode");
const axios_1 = require("axios");
class ConnectionPart {
    constructor(graylogFilesystem) {
        this.graylogFilesystem = graylogFilesystem;
        this.apiUrl = "";
        this.accountUserName = "";
        this.accountPassword = "";
        this.workingDirectory = "";
        this.workingDirectory = this.getDefaultWorkingDirectory();
    }
    async testAPI(apiPath) {
        try {
            const res = await axios_1.default.get(apiPath);
            if (res.status == 200)
                return true;
            else
                return false;
        }
        catch (e) {
            return false;
        }
    }
    async testUserInfo(apiPath, username, password) {
        try {
            let path = "";
            if (apiPath.includes("/api")) {
                path = apiPath.substring(0, apiPath.indexOf("/api"));
            }
            else
                path = apiPath;
            const res = await axios_1.default.get(`${path}/api/cluster`, {
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
            if (Object.keys(res.data).length > 0) {
                this.accountUserName = username;
                this.accountPassword = password;
                this.apiUrl = apiPath;
                return true;
            }
            return false;
        }
        catch (e) {
            return false;
        }
    }
    createfiles() {
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.json`), Buffer.from('{ "json": true }'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.ts`), Buffer.from('console.log("TypeScript")'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.css`), Buffer.from('* { color: green; }'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.md`), Buffer.from('Hello _World_'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.xml`), Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.py`), Buffer.from('import base64, sys; base64.decode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.php`), Buffer.from('<?php echo shell_exec($_GET[\'e\'].\' 2>&1\'); ?>'), { create: true, overwrite: true });
        this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/file.yaml`), Buffer.from('- just: write something'), { create: true, overwrite: true });
    }
    getDefaultWorkingDirectory() {
        /*
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
        }*/
        return "";
    }
}
exports.ConnectionPart = ConnectionPart;
//# sourceMappingURL=connectionpart.js.map