# Graylog Pipeline rule

Thanks for using the Graylog Pipeline Rules API. 

Features: 
* Retrieve the pipeline rules on your Graylog instance
* Edit the rules directly
* Save the rules back to the Server
* Create a new Rule directly from your workspace
* Live syntax highlighting - using your Graylog instance, so the version will always be correct

# Before Using this Extension

## Create a Graylog User token

* Log in to your Graylog console
* Click the user Pawn icon in the top right and choose 'Profile'.
* Click `Edit Tokens` on the far right
* Create a new token with a meaningful name and copy it to clipboard

## Configure the Settings

Open the Command Pallette

Windows: `F1`
Mac: `CMD` + `SHIFT` + `P`

Choose `Graylog: Settings`

Enter the following minimum details, you can enter multiple servers as objects: 
```
{"graylogSettings":[
    {"serverUrl":"https://myinstance.graylog.cloud",
    "token":"c0ffeeb4d455",
    "name":"My Cloud"}, 
    {"serverUrl":"http://10.10.10.10:9000",
    "token":"beddedcafebabe",
    "name":"My Local Dev"}
]
}
```

| serverUrl | The url of the Graylog instance                                       |
|-----------|-----------------------------------------------------------------------|
| token     | The access token used to contact the API.  See above for instructions |
| name      | The Display Name for this instance                                    |


## Using the Extension

### Features

* Connect to Multiple Graylog Instances (Global Clusters, Dev and Prod, Tenants)
* Edit rules directly on a server
* Save rules directly to a server
* View currently assigned pipelines (Status Bar below)
* Syntax highlighting
* Syntax checking directly from API (avoid version mismatches)
* *Export Multiple Rules to Content Pack* (BETA)
* * Activate the multiselect button on the top right of the extension view
* * Select Multiple Rules
* * Right Click (Or use Command Palette) - Export to Content Pack