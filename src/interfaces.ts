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
    apiHostUrl: string,
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