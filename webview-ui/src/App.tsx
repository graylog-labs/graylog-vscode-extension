import { vscode } from "./utilities/vscode";
import { VSCodeDropdown, VSCodeOption, VSCodeProgressRing, VSCodeTextArea } from "@vscode/webview-ui-toolkit/react";
import { useEffect, useRef, useState } from "react";
import Prism from "prismjs";
import 'prismjs/components/prism-json';
import 'prismjs/themes/prism-okaidia.css';
import "./App.css";
import "./codicon.css";

function App() {
  const [serversInfo, setServersInfo] = useState<{name: string, token: string, serverUrl: string}[]>([]);
  const [url, setUrl] = useState("");
  const [pattern, setPattern] = useState("");
  const [sampleData, setSampleData] = useState("");
  const [output, setOutput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const abortRef = useRef<any>();
  const timeoutId = useRef<NodeJS.Timeout>();

  const onMessage = (event: any) => {
    const message = event.data;

    switch (message.command) {
        case 'serversInfo':
          setServersInfo(message.serversInfo);
          if(message.serversInfo.length > 0) {
            setUrl(message.serversInfo[0].serverUrl);
          }
          break;
        case "testPatternResult":
          const {success, ...result} = message.result;
          if(success) {
            setOutput(JSON.stringify(result, null, 2));
          }
          setLoading(false);
          break;
        case "error":
          setError(message.error);
          setLoading(false);
          break;
        case "abort":
          abortRef.current = message.abort;
          break;
        default:
          console.log({message});
          break;
    }
  };
  console.log({error});
  useEffect(() => {

    const state: Record<string, string> = vscode.getState() as any;

    if(state){
      setUrl(state.url || "");
      setPattern(state.pattern || "");
      setSampleData(state.sampleData || "");
      setOutput(state.output || "");
    }

    vscode.postMessage({
      command: "getServersInfo",
    });

    window.addEventListener("message", onMessage);

    return () => {
      window.removeEventListener("message", onMessage);
    };
  }, []);

  function handleRun(){
    if(abortRef.current) {
      console.log("aborting", abortRef.current);
      abortRef.current();
    }
    const body = {
      grok_pattern: {
        name: "vscode_extension_test",
        pattern,
      },
      sampleData
    };

    vscode.postMessage({
      command: "testPattern",
      text: JSON.stringify({
        url,
        token: serversInfo.find((server: any) => server.serverUrl === url)?.token,
        body,
      })
    });
    setLoading(true);
  };

  useEffect(() => {
    vscode.setState({ url, pattern, sampleData, output });
  }, [url, pattern, sampleData, output]);

  useEffect(() => {
    setOutput("");
    setError("");
    if(timeoutId.current) {
      clearTimeout(timeoutId.current);
    }
    if(pattern){
      timeoutId.current = setTimeout(() => {
        handleRun();
      }, 1000);
    }
  }, [url, pattern, sampleData]);

  useEffect(() => {
    Prism.highlightAll();
  }, [output]);

  return (
    <main>
      <h1>Test Grok Pattern!</h1>
      <div id="content">
        <div id="inputs_container">
          <div className="dropdown-container">
            <label htmlFor="servers-dropdown">Select server</label>
            <VSCodeDropdown
              id="servers-dropdown"
              position="below"
              value={url}
              onChange={(e: any) => setUrl(e.target.value)}
            >
              {serversInfo.map((server: any) => (
                <VSCodeOption key={server.token} value={server.serverUrl}>{server.name}</VSCodeOption>
              ))}
            </VSCodeDropdown>
          </div>
          <div id="pattern-input-container">
            <VSCodeTextArea rows={3} value={pattern} onInput={(e: any) => setPattern(e.target.value)} id="pattern-input">
              Pattern
            </VSCodeTextArea>
            <p>{error}</p>
          </div>
          <VSCodeTextArea rows={20} value={sampleData} onInput={(e: any) => setSampleData(e.target.value)}>
            Sample Data
          </VSCodeTextArea>
        </div>

        <div id="output_container">
          <p>
            <span>Output</span>
            {loading && <VSCodeProgressRing id="progress_ring" />}
          </p>
          <pre>
            <code className="language-json">
              {output}
            </code>
          </pre>
        </div>
      {/* <VSCodeTextArea id="output" rows={30} value={output} readOnly>
        Output
      </VSCodeTextArea> */}
      </div>
    </main>
  );
}

export default App;
