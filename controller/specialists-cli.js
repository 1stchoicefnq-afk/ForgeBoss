#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path');
const {routeSpecialists,composePrompt}=require('./lib/specialists');
const ROOT=path.resolve(__dirname,'..');
function arg(n,d=''){const i=process.argv.indexOf(n);return i>=0?process.argv[i+1]:d;}
const cmd=process.argv[2]||'route',input=arg('--input'),mode=arg('--mode','builder'),output=arg('--output');
if(!input)throw new Error('--input is required');
const packet=JSON.parse(fs.readFileSync(input,'utf8'));
const builder=String(arg('--builder-specialists','')).split(',').filter(Boolean);
const routing=routeSpecialists(ROOT,packet,{mode,builderSpecialists:builder});
const result={routing,composition:composePrompt(ROOT,packet,routing,{mode})};
const text=JSON.stringify(result,null,2);
if(output)fs.writeFileSync(output,text);else process.stdout.write(text);
