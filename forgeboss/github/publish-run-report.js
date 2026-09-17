#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {githubWrite}=require('./write-gate');
const ROOT=path.resolve(__dirname,'..','..'),cfg=JSON.parse(fs.readFileSync(path.join(ROOT,'controller','config.default.json'),'utf8'));
const arg=(n,d)=>{const i=process.argv.indexOf(n);return i>=0?process.argv[i+1]:d};
const md=arg('--markdown'),pr=Number(arg('--pr','168')),c=cfg.control||{},g=c.github_app||{};
const owner=c.owner,repo=c.repo,appId=String(g.app_id||''),iid=String(g.installation_id||''),pem=String(g.pem_path||'').replace('%USERPROFILE%',process.env.USERPROFILE||'');
if(!md||!fs.existsSync(md))throw new Error('run report markdown missing');
if(!fs.existsSync(pem))throw new Error('GitHub App private key missing: '+pem);
const report=fs.readFileSync(md,'utf8');
const digest=crypto.createHash('sha256').update(report).digest('hex');
const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url'),now=Math.floor(Date.now()/1000);
const u=b64({alg:'RS256',typ:'JWT'})+'.'+b64({iat:now-60,exp:now+540,iss:appId});
const jwt=u+'.'+crypto.sign('RSA-SHA256',Buffer.from(u),fs.readFileSync(pem)).toString('base64url');
(async()=>{
 let r=await githubWrite(`https://api.github.com/app/installations/${iid}/access_tokens`,{method:'POST',headers:{Authorization:`Bearer ${jwt}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},body:JSON.stringify({repositories:[repo],permissions:{issues:'write',pull_requests:'read',contents:'read'}})});
 if(!r.ok)throw new Error(`installation token HTTP ${r.status}: `+await r.text());const tok=(await r.json()).token;
 r=await githubWrite(`https://api.github.com/repos/${owner}/${repo}/issues/${pr}/comments`,{method:'POST',headers:{Authorization:`Bearer ${tok}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},body:JSON.stringify({body:report})},`comment:${owner}/${repo}:${pr}:${digest}`);
 if(r.deduplicated){console.log(JSON.stringify({ok:true,deduplicated:true,pull_request:pr}));return}
 if(!r.ok)throw new Error(`comment HTTP ${r.status}: `+await r.text());const j=await r.json();console.log(JSON.stringify({ok:true,comment_id:j.id,html_url:j.html_url,pull_request:pr}));
})().catch(e=>{console.error(e.stack||e.message);process.exit(2)});
