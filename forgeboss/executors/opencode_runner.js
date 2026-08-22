"use strict";
const {spawnSync}=require("child_process"),fs=require("fs"),path=require("path");
if(process.argv.length<4){console.error("usage: node opencode_runner.js PACKET.json WORKSPACE");process.exit(2)}
if(process.env.FORGEBOSS_ALLOW_PAID_EXECUTOR!=="YES"){console.error("FORGEBOSS SAFE STOP: paid executor gate disabled.");process.exit(3)}
if(process.env.FORGEBOSS_ENABLE_QUARANTINED_OPENCODE!=="YES"){console.error("FORGEBOSS SECURITY STOP: OpenCode host-shell executor is QUARANTINED until OS isolation exists.");process.exit(13)}
const packetPath=path.resolve(process.argv[2]),workspace=path.resolve(process.argv[3]);
const lease=process.env.FORGEBOSS_EXECUTOR_LEASE||"",token=process.env.FORGEBOSS_EXECUTOR_LEASE_TOKEN||"";
if(!lease||!token){console.error("FORGEBOSS SAFE STOP: unified executor lease missing.");process.exit(13)}
const py=process.env.FORGEBOSS_PYTHON||"python",guard=path.resolve(__dirname,"..","security","executor_guard.py");
let v=spawnSync(py,[guard,"verify","--lease",lease,"--token",token,"--packet",packetPath,"--workspace",workspace,"--executor","opencode"],{encoding:"utf8",shell:false,windowsHide:true});
if(v.status!==0){console.error("FORGEBOSS SAFE STOP: "+(v.stdout||v.stderr));process.exit(13)}
const packet=JSON.parse(fs.readFileSync(packetPath,"utf8"));
const prompt=["You are an execution worker inside ForgeBoss.",`Objective: ${packet.objective||""}`,`Allowed writes ONLY: ${JSON.stringify(packet.allowed_files||[])}`,"Never push, merge, deploy, alter GitHub state, access secrets, or widen scope."].join("\n");
const env={...process.env};for(const k of ["GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT","FORGEBOSS_EXECUTOR_LEASE_TOKEN"])delete env[k];
const r=spawnSync("opencode",["run","--format","json","--model",process.env.FORGEBOSS_OPENCODE_MODEL||"openai/gpt-5.6-luna",prompt],{cwd:workspace,encoding:"utf8",shell:false,timeout:900000,windowsHide:true,env});
process.stdout.write(r.stdout||"");process.stderr.write(r.stderr||"");if(r.error)process.exit(4);if((r.status??5)!==0)process.exit(r.status??5);
let p=spawnSync(py,[guard,"postflight","--lease",lease,"--token",token,"--packet",packetPath,"--workspace",workspace,"--executor","opencode"],{encoding:"utf8",shell:false,windowsHide:true});
if(p.status!==0){console.error("FORGEBOSS postflight denied OpenCode result: "+(p.stdout||p.stderr));process.exit(13)}
