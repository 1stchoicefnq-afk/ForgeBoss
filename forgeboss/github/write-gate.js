'use strict';
const {githubRequest}=require('./request-governor');
async function githubWrite(url,options={},key=''){return githubRequest(url,options,{dedupeKey:key||''})}
module.exports={githubWrite};
