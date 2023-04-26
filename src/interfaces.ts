import * as vscode from 'vscode';

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

export interface apiInstance{
    serverUrl: string,
    token: string,
    name: string
}

export enum TreeViewModes{
    normalMode =1,
    selectMode =2
}

export enum createEditStatus{
    create = 1,
    edit = 2,
    normal = 3
}

export interface PipleLine{
    id: string,
    title: string,
    description: string,
    source: string,
    stages: Array<any>,
    errors: null | Array<any>,
    usedInRules: Array<string>
}

export interface ServerInfo{
    serverUrl: string,
    token: string,
    name: string
}

export interface Setting{
    serverList: ServerInfo[]
}