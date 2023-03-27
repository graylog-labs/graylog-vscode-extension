# Graylog Pipeline rule

Thanks for using the Graylog Pipeline Rules API. 

Features: 
* Retrieve the pipeline rules on your Graylog instance
* Edit the rules directly
* Save the rules back to the Server
* Create a new Rule directly from your workspace
* Live syntax highlighting - using your Graylog instance, so the version will always be correct


# Getting Started

## Installation

1. Clone this repo locally using VSCode
2. Open the Command Pallette:
    * Windows: `F1` or `Ctrl` + `Shift` + `P`
    * Mac: `F1` or `Cmd` + `Shift` + `P`
3. Type (or copy/paste): `developer: install extension from Location` 
4. Choose path created from cloning the repo locally

## Create a Graylog User token

* Log in to your Graylog console
* Click the user Pawn icon in the top right and choose 'Profile'.
* Click `Edit Tokens` on the far right
* Create a new token with a meaningful name and copy it to clipboard

## Configure the Extension

Open the Command Pallette

Windows: `F1`
Mac: `CMD` + `SHIFT` + `P`

Choose `Graylog: Setup Workspace`

Enter the address of your preferred Graylog instance - either self-hosted `http://10.10.100.100:9000` or Cloud `https://myinstance.graylog.cloud` and enter the token when requested. 

## Using the Extension

You will now have a new folder in your Workspace.  In order to retrieve this repeatably, you must save the workspace.  It is a good habit to refresh any running Web versions of the console to ensure you have the latest iterations.  
