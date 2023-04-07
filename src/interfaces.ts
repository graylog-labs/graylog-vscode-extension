
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
