"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectionPart = void 0;
const vscode = require("vscode");
const fs = require("fs");
class ConnectionPart {
    constructor(graylogFilesystem) {
        this.graylogFilesystem = graylogFilesystem;
        this.workingDirectory = "";
        this.workingDirectory = this.getDefaultWorkingDirectory();
    }
    getDefaultWorkingDirectory() {
        if (fs.existsSync("C:\\")) {
            if (!fs.existsSync("C:\\")) {
                fs.mkdirSync("C:\\.gray_log");
            }
            return "C:\\.gray_log";
        }
        if (fs.existsSync("/bin")) {
            this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/.garylog/`));
            this.graylogFilesystem.createDirectory(vscode.Uri.parse(`graylog:/.garylog/setting.json`));
            this.graylogFilesystem.writeFile(vscode.Uri.parse(`graylog:/.garylog/setting.json`), Buffer.from(`{
                username:'',
                password:'',
            }`), { create: true, overwrite: true });
            return "graylog://.graylog";
        }
        return "";
    }
}
exports.ConnectionPart = ConnectionPart;
//# sourceMappingURL=connectionpart.js.map