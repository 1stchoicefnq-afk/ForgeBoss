import json,shutil,subprocess
from pathlib import Path
def w(p,s):p.write_text(s,encoding="utf-8")
def make(root,cat):
 shutil.rmtree(root,ignore_errors=True);root.mkdir(parents=True)
 d={"database":("retry.js","exports.retryable=c=>['40001'].includes(c)\n","const a=require('./retry');if(!a.retryable('40001')||!a.retryable('40P01')||a.retryable('23505'))process.exit(1)\n"),"backend":("api.js","exports.create=x=>({status:201,body:x})\n","const a=require('./api');if(a.create(null).status!==400||a.create({name:'x'}).status!==201)process.exit(1)\n"),"auth":("auth.js","exports.allowed=m=>true\n","const a=require('./auth');if(a.allowed(null)!==false||a.allowed({active:true})!==true)process.exit(1)\n"),"frontend":("ui.js","exports.toggle=x=>x\n","const u=require('./ui');if(u.toggle(false)!==true||u.toggle(true)!==false)process.exit(1)\n"),"small_bug":("util.js","exports.last=a=>a[a.length]\n","const u=require('./util');if(u.last([1,2,3])!==3)process.exit(1)\n"),"ci":("check.js","process.exit(1)\n","const c=require('./check')\n"),"tests":("calc.js","exports.clamp=(n,min,max)=>Math.min(max,n)\n","const c=require('./calc');if(c.clamp(-2,0,10)!==0||c.clamp(20,0,10)!==10)process.exit(1)\n")}
 if cat=="refactor":
  w(root/"a.js","exports.norm=s=>String(s).trim().toLowerCase()\n");w(root/"b.js","exports.norm=s=>String(s).trim().toLowerCase()\n");w(root/"test.js","const a=require('./a'),b=require('./b');if(a.norm(' X ')!=='x'||b.norm(' Y ')!=='y')process.exit(1)\n");allowed=["a.js","b.js","normalize.js","test.js"]
 else:
  fn,code,test=d[cat];w(root/fn,code);w(root/"test.js",test);allowed=[fn,"test.js"]
 packet={"objective":f"Fix this controlled {cat} benchmark so node test.js passes. Make the smallest correct change.","allowed_files":allowed,"context_files":allowed,"acceptance_criteria":["node test.js exits 0"]};w(root/"packet.json",json.dumps(packet,indent=2))
 subprocess.run(["git","init"],cwd=root,capture_output=True);subprocess.run(["git","config","user.email","forgeboss@local"],cwd=root);subprocess.run(["git","config","user.name","ForgeBoss"],cwd=root);subprocess.run(["git","add","."],cwd=root);subprocess.run(["git","commit","-m","fixture"],cwd=root,capture_output=True);return packet
