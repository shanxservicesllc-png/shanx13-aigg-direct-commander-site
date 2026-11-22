// ShanX13 AiGG / Direct Commander — independent Cloudflare customer portal.
// Security boundary: no device commands, no credentials in source, no X13 ledger writes.
// Production disabled without verified Cloudflare Access audience, owner allowlist and D1.
const HEADERS={"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer"};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:HEADERS});
const bytes = s=>new TextEncoder().encode(s);
const email = s=>typeof s==="string"&&s.length<=254&&/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)?s.toLowerCase():"";
const valid = (s,regex)=>typeof s==="string"&&regex.test(s);
const bearer=(req)=>{const v=req.headers.get("authorization")||"";return v.startsWith("Bearer ")?v.slice(7):""};
const base64urlDecode=s=>{
  if(!valid(s,/^[A-Za-z0-9_-]{1,20000}$/))throw Error("Bad token encoding");
  const b=s.replace(/-/g,"+").replace(/_/g,"/");const bin=atob(b+"=".repeat((4-b.length%4)%4));
  return Uint8Array.from(bin,ch=>ch.charCodeAt(0));
};
const parseTokenPart=s=>JSON.parse(new TextDecoder().decode(base64urlDecode(s)));
export async function verifyCloudflareAccessJWT(jwt,env,fetcher=fetch,now=Math.floor(Date.now()/1000)){
  const host=String(env?.ACCESS_TEAM_DOMAIN||"").trim().toLowerCase();
  if(!valid(host,/^[a-z0-9-]+\.cloudflareaccess\.com$/)||!env?.ACCESS_AUD||!jwt||jwt.length>20000)return null;
  try{
    const parts=jwt.split(".");if(parts.length!==3)return null;
    const header=parseTokenPart(parts[0]),claims=parseTokenPart(parts[1]);
    if(header.alg!=="RS256" || !valid(header.kid,/^[\w-]{1,128}$/))return null;
    const audiences=Array.isArray(claims.aud)?claims.aud:[claims.aud];
    if(claims.iss!=="https://"+host||!audiences.includes(env.ACCESS_AUD))return null;
    if(!Number.isInteger(claims.exp)||claims.exp<=now||claims.exp>now+86400)return null;
    if(claims.nbf && (claims.nbf>now+120 || !Number.isInteger(claims.nbf)))return null;
    if(claims.iat && (claims.iat>now+120 || !Number.isInteger(claims.iat)))return null;
    const userEmail=email(claims.email);if(!userEmail)return null;
    const res=await fetcher("https://"+host+"/cdn-cgi/access/certs",{headers:{accept:"application/json"}});
    if(!res.ok)return null;
    const data=await res.json();
    const jwk=(data.keys||[]).find(k=>k.kid===header.kid&&k.kty==="RSA"&&(k.alg==="RS256"||!k.alg));
    if(!jwk)return null;
    const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
    if(!await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,base64urlDecode(parts[2]),bytes(parts[0]+"."+parts[1])))return null;
    return {email:userEmail,subject:String(claims.sub||"")};
  }catch{return null}
}
export const sha256=async s=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes(s))),b=>b.toString(16).padStart(2,"0")).join("");
const stmt=(db,q,...a)=>db.prepare(q).bind(...a);
const parseRequest=async(req,cap=2500)=>{
  const declared=Number(req.headers.get("content-length")||"0");if(declared>cap)throw Error("Too large");
  const text=await req.text();if(text.length>cap)throw Error("Too large");
  const value=JSON.parse(text);if(!value||typeof value!=="object"||Array.isArray(value))throw Error("Bad body");
  return value;
};
const configured=env=>!!(env?.DB&&env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD&&env.OWNER_EMAILS);
async function currentViewer(req,env){
  const identity=await verifyCloudflareAccessJWT(req.headers.get("CF-Access-Jwt-Assertion"),env);
  if(!identity)return null;
  const owners=String(env.OWNER_EMAILS).split(",").map(x=>email(x.trim())).filter(Boolean);
  if(owners.includes(identity.email))return {...identity,role:"owner",tenant:"owner"};
  const account=await stmt(env.DB,"SELECT tenant_id,role,subscription_status FROM accounts WHERE email=? AND active=1",identity.email).first();
  return account?{...identity,role:account.role,tenant:account.tenant_id,subscription_status:account.subscription_status}:null;
}
const accessResponse=()=>json({error:"Unauthorized or account not enrolled"},401);
export async function handleRequest(req,env){
  const url=new URL(req.url);const path=url.pathname;
  if(path==="/healthz")return json({product:"ShanX13 AiGG Direct Commander",online:true,customer_login:false,device_execution:false});
  if(!configured(env))return json({error:"Service not provisioned"},503);
  if(path==="/api/agent/events"){
    if(req.method!=="POST")return json({error:"Method not allowed"},405);
    const token=bearer(req);
    if(!valid(token,/^[A-Za-z0-9_-]{43,128}$/))return accessResponse();
    const digest=await sha256(token);
    const agent=await stmt(env.DB,"SELECT agent_id,tenant_id,device_id FROM agents WHERE token_hash=? AND active=1",digest).first();
    if(!agent)return accessResponse();
    try{
      const x=await parseRequest(req,1600);
      if(!valid(x.event_id,/^[a-zA-Z0-9_-]{12,96}$/) ||
        !["mcp_call","file_read","file_write","workflow"].includes(x.kind) ||
        !["accepted","failed","completed","verified"].includes(x.outcome) ||
        !Number.isInteger(x.units)||x.units<0||x.units>1000000)return json({error:"Invalid event"},400);
      const stored=await stmt(env.DB,
        "INSERT OR IGNORE INTO usage_events(event_id,tenant_id,agent_id,device_id,kind,outcome,units,created_at) VALUES(?,?,?,?,?,?,?,?)",
        x.event_id,agent.tenant_id,agent.agent_id,agent.device_id,x.kind,x.outcome,x.units,new Date().toISOString()).run();
      return json({stored:stored.meta?.changes===1,duplicate:stored.meta?.changes===0},202);
    }catch{return json({error:"Bad event"},400)}
  }
  const viewer=await currentViewer(req,env);if(!viewer)return accessResponse();
  if(path==="/"||path==="/portal"){
    if(req.method!=="GET")return json({error:"Method not allowed"},405);
    const nonce=crypto.randomUUID().replaceAll("-","");
    return new Response(portalHTML(nonce),{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer","x-frame-options":"DENY","content-security-policy":"default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"}});
  }
  if(path==="/api/me"&&req.method==="GET")return json({email:viewer.email,role:viewer.role,tenant_id:viewer.tenant});
  if(path==="/api/usage"&&req.method==="GET"){
    const all=viewer.role==="owner";const where=all?"":" WHERE tenant_id=?";const params=all?[]:[viewer.tenant];
    const total=await stmt(env.DB,"SELECT COUNT(*) AS requests,COALESCE(SUM(units),0) AS units,COUNT(DISTINCT device_id) AS devices FROM usage_events"+where,...params).first();
    const events=await stmt(env.DB,"SELECT kind,outcome,device_id,created_at AS at FROM usage_events"+where+" ORDER BY created_at DESC LIMIT 30",...params).all();
    return json({viewer:{email:viewer.email,role:viewer.role},period:"all recorded events",total:{
      requests:Number(total?.requests||0),units:Number(total?.units||0),devices:Number(total?.devices||0)},events:events.results||[]});
  }
  if(path==="/api/admin/accounts"&&viewer.role==="owner"&&req.method==="GET"){
    const rows=await env.DB.prepare("SELECT email,tenant_id,role,active,subscription_status FROM accounts ORDER BY email LIMIT 200").all();
    return json({accounts:rows.results||[]});
  }
  if(path==="/api/admin/accounts"&&viewer.role==="owner"&&req.method==="POST"){
    try{
      const x=await parseRequest(req);const e=email(x.email);
      if(!e||e===viewer.email)return json({error:"Invalid email"},400);
      const tenant=crypto.randomUUID();
      await stmt(env.DB,"INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,1,'pending')",
        e,tenant,"customer").run();
      return json({created:true,email:e,tenant_id:tenant,subscription_status:"pending"},201);
    }catch{return json({error:"Account not created"},400)}
  }
  if(path==="/api/admin/agents"&&viewer.role==="owner"&&req.method==="POST"){
    try{
      const x=await parseRequest(req);
      if(!valid(x.device_id,/^[a-z0-9-]{3,64}$/)||!valid(x.tenant_id,/^[a-zA-Z0-9_-]{4,64}$/))return json({error:"Invalid device"},400);
      if(x.tenant_id!=="owner"){
        const account=await stmt(env.DB,"SELECT 1 FROM accounts WHERE tenant_id=? AND active=1",x.tenant_id).first();
        if(!account)return json({error:"Tenant unavailable"},404);
      }
      const secret=Array.from(crypto.getRandomValues(new Uint8Array(48)),b=>b.toString(16).padStart(2,"0")).join("");
      const agent=crypto.randomUUID();
      await stmt(env.DB,"INSERT INTO agents(agent_id,tenant_id,device_id,token_hash,active) VALUES(?,?,?,?,1)",
        agent,x.tenant_id,x.device_id,await sha256(secret)).run();
      return json({created:true,agent_id:agent,tenant_id:x.tenant_id,device_id:x.device_id,one_time_token:secret},201);
    }catch{return json({error:"Enrollment rejected"},400)}
  }
  if(path==="/api/admin/agents/revoke"&&viewer.role==="owner"&&req.method==="POST"){
    try{
      const x=await parseRequest(req);
      if(!valid(x.agent_id,/^[a-f0-9-]{36}$/))return json({error:"Invalid agent"},400);
      const response=await stmt(env.DB,"UPDATE agents SET active=0 WHERE agent_id=? AND active=1",x.agent_id).run();
      return json({revoked:response.meta?.changes===1});
    }catch{return json({error:"Invalid request"},400)}
  }
  return json({error:"Not found or not permitted"},404);
}
const portalHTML=nonce=>'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>ShanX13 AiGG | Account Center</title><style nonce="'+nonce+'">'+
  ':root{font:15px system-ui,sans-serif;color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#091b11;color:#edf7e8}header{padding:20px max(24px,calc((100vw - 1090px)/2));background:#153322;border-bottom:1px solid #5a7450;display:flex;justify-content:space-between;gap:20px;align-items:center}header b{font-size:19px}header b em{color:#e9c17a;font-style:normal}header small{font-size:9px;letter-spacing:.1em;color:#b7ea8e}main{max-width:1090px;margin:55px auto;padding:0 24px}h1{font-size:clamp(30px,4vw,50px);letter-spacing:-.06em;margin:12px 0 8px}p{color:#acc4ad}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-top:34px}.card,.events{background:#153523;border:1px solid #486f4c;border-radius:14px;padding:27px}.card small{font-size:10px;letter-spacing:.07em;color:#abc5a2}.card strong{font-size:33px;display:block;margin-top:14px}.events{margin-top:18px}.events b{color:#e8cb78}.events ul{list-style:none;padding:0}.events li{padding:13px 0;border-top:1px solid #335640;color:#b6cbb4;font-size:12px}.warn{color:#efb88d}button{border:0;border-radius:8px;background:#c4ef91;color:#12301a;padding:12px 18px;font-weight:800;cursor:pointer}a{color:#d2eba5}@media(max-width:650px){.cards{grid-template-columns:1fr}header{display:block}}'+
  '</style></head><body><header><b>SHANX13 <em>AIGG</em> <small>/ ACCOUNT CENTER</small></b><div><span id="viewer">Authenticating</span> · <a href="https://shanxservicesllc-png.github.io/shanx13-aigg-direct-commander-site/">Product website</a></div></header>'+
  '<main><div style="font-size:11px;letter-spacing:.17em;color:#dbbd75">ACCOUNT / AUTHENTICATED USAGE</div><h1>Your direct operations.</h1><p id="state">Retrieving verified database records.</p>'+
  '<div class="cards"><div class="card"><small>RECORDED CALLS</small><strong id="calls">—</strong></div><div class="card"><small>USAGE UNITS</small><strong id="units">—</strong></div><div class="card"><small>OBSERVED DEVICES</small><strong id="devices">—</strong></div></div>'+
  '<div class="events"><b>Recent verified source events</b><ul id="eventList"><li>Awaiting authenticated data.</li></ul></div><p style="margin-top:30px"><button id="refresh">Refresh usage</button></p></main>'+
  '<script nonce="'+nonce+'">async function load(){let state=document.getElementById("state");try{let r=await fetch("/api/usage",{cache:"no-store",credentials:"same-origin"});if(!r.ok)throw Error("Usage unavailable ("+r.status+")");let d=await r.json();let set=(id,v)=>document.getElementById(id).textContent=String(v);set("viewer",d.viewer.email+" / "+d.viewer.role);set("calls",d.total.requests);set("units",d.total.units);set("devices",d.total.devices);state.textContent="Values reflect database records only. Period: "+d.period;let ul=document.getElementById("eventList");ul.replaceChildren();if(!d.events.length){let li=document.createElement("li");li.textContent="No recorded events.";ul.append(li)}d.events.forEach(e=>{let li=document.createElement("li");li.textContent=e.kind+" / "+e.outcome+" / "+e.device_id+" / "+e.at;ul.append(li)});}catch(e){state.className="warn";state.textContent="NOT VERIFIED: "+e.message;}}document.getElementById("refresh").addEventListener("click",load);load();</script></body></html>';
export default {fetch:handleRequest};
