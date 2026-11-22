import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {verifyCloudflareAccessJWT,handleRequest,sha256} from '../worker.mjs';

const host='shanx-test.cloudflareaccess.com';
const audience='test-audience-dedicated';
const owner='owner@example.test';
let privateKey, jwk, originalFetch, testJWT;
const json = x => Buffer.from(JSON.stringify(x)).toString('base64url');
async function signedJWT(payload,headerExtra={}){
 const h=json({alg:'RS256',kid:'test-signing-key',typ:'JWT',...headerExtra});
 const p=json(payload);
 const sig=new Uint8Array(await webcrypto.subtle.sign('RSASSA-PKCS1-v1_5',privateKey,new TextEncoder().encode(h+'.'+p)));
 return h+'.'+p+'.'+Buffer.from(sig).toString('base64url');
}
function claims(overrides={}){
 const n=Math.floor(Date.now()/1000);
 return {iss:'https://'+host,aud:[audience],exp:n+300,iat:n-3,sub:'user-test-id',email:owner,...overrides};
}
function responseJson(obj,status=200){return new Response(JSON.stringify(obj),{status,headers:{'content-type':'application/json'}})}
function env(db){return {DB:db,ACCESS_TEAM_DOMAIN:host,ACCESS_AUD:audience,OWNER_EMAILS:owner}}
function request(path='/',token=testJWT,method='GET',body,headers={}){
 return new Request('https://portal.example.test'+path,{method,headers:{...(token?{'CF-Access-Jwt-Assertion':token}:{}),...headers,...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
}
function fakeDb(){
 const rows=[],accounts=[],agents=[];
 function prepare(q){
  let args=[];
  return {bind(...v){args=v;return this},async first(){
    if(q.includes('SELECT tenant_id,role,subscription_status'))return accounts.find(a=>a.email===args[0]&&a.active);
    if(q.includes('SELECT agent_id,tenant_id,device_id'))return agents.find(a=>a.token_hash===args[0]&&a.active);
    if(q.includes('SELECT 1 FROM accounts WHERE tenant_id'))return accounts.find(a=>a.tenant_id===args[0]&&a.active)?{'1':1}:null;
    if(q.includes('SELECT COUNT(*) AS requests')){
     const a=q.includes('WHERE tenant_id=?')?rows.filter(r=>r.tenant_id===args[0]):rows;
     return {requests:a.length,units:a.reduce((v,r)=>v+r.units,0),devices:new Set(a.map(r=>r.device_id)).size};
    }
    return null;
   },async all(){
    if(q.includes('SELECT kind,outcome,device_id')) {
     const a=q.includes('WHERE tenant_id=?')?rows.filter(r=>r.tenant_id===args[0]):rows;
     return {results:a.map(r=>({kind:r.kind,outcome:r.outcome,device_id:r.device_id,at:r.created_at}))};
    }
    if(q.includes('SELECT email,tenant_id'))return {results:accounts};
    return {results:[]};
   },async run(){
    if(q.includes('INSERT OR IGNORE INTO usage_events')){
     const [event_id,tenant_id,agent_id,device_id,kind,outcome,units,created_at]=args;
     if(rows.find(r=>r.event_id===event_id))return {meta:{changes:0}};
     rows.push({event_id,tenant_id,agent_id,device_id,kind,outcome,units,created_at});
     return {meta:{changes:1}};
    }
    if(q.includes('INSERT INTO accounts')){
     const [email,tenant_id,role]=args;
     if(accounts.find(a=>a.email===email))throw Error('duplicate');
     accounts.push({email,tenant_id,role,active:1,subscription_status:'pending'});
     return {meta:{changes:1}};
    }
    if(q.includes('INSERT INTO agents')){
     const [agent_id,tenant_id,device_id,token_hash]=args;
     if(agents.find(a=>a.device_id===device_id&&a.tenant_id===tenant_id))throw Error('duplicate');
     agents.push({agent_id,tenant_id,device_id,token_hash,active:1});
     return {meta:{changes:1}};
    }
    if(q.includes('UPDATE agents SET active=0')){
     const a=agents.find(a=>a.agent_id===args[0]&&a.active);
     if(a)a.active=0;
     return {meta:{changes:a?1:0}};
    }
    return {meta:{changes:0}};
   }};
 }
 return {prepare,rows,accounts,agents};
}

test('prepare signed JWT fixture and fetch stub',async()=>{
 originalFetch=globalThis.fetch;
 const kp=await webcrypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 privateKey=kp.privateKey;jwk=await webcrypto.subtle.exportKey('jwk',kp.publicKey);
 jwk.kid='test-signing-key';jwk.alg='RS256';
 globalThis.fetch=async() => responseJson({keys:[jwk]});
 testJWT=await signedJWT(claims());
 assert.equal(typeof testJWT,'string');
});
test('valid signed Cloudflare Access identity',async()=>{
 const v=await verifyCloudflareAccessJWT(testJWT,env({}));
 assert.equal(v?.email,owner);
});
test('reject forged signature, wrong audience, expiration, wrong issuer and unsigned JWT',async()=>{
 const e=env({});
 const bad=await signedJWT(claims({aud:['wrong-audience']}));
 assert.equal(await verifyCloudflareAccessJWT(bad,e),null);
 assert.equal(await verifyCloudflareAccessJWT(await signedJWT(claims({exp:1})),e),null);
 assert.equal(await verifyCloudflareAccessJWT(await signedJWT(claims({iss:'https://evil.example'})),e),null);
 assert.equal(await verifyCloudflareAccessJWT(await signedJWT(claims(),{alg:'none'}),e),null);
 const forged=testJWT.slice(0,-8)+'ABCDEFGH';
 assert.equal(await verifyCloudflareAccessJWT(forged,e),null);
 assert.equal(await verifyCloudflareAccessJWT('',e),null);
});
test('unprovisioned portal fails closed, health probe makes no readiness claim',async()=>{
 const res=await handleRequest(request('/api/usage',null),{});
 assert.equal(res.status,503);
 const h=await handleRequest(request('/healthz',null),{});
 assert.equal(h.status,200);
 assert.equal((await h.json()).customer_login,false);
});
test('no JWT never authenticates an owner',async()=>{
 const r=await handleRequest(request('/api/usage',null),env(fakeDb()));
 assert.equal(r.status,401);
});
test('verified owner sees only true database records, no fabricated counts',async()=>{
 const db=fakeDb();
 const r=await handleRequest(request('/api/usage'),env(db));
 assert.equal(r.status,200);
 const data=await r.json();
 assert.deepEqual(data.total,{requests:0,units:0,devices:0});
 assert.equal(data.events.length,0);
 const portal=await handleRequest(request('/portal'),env(db));
 assert.equal(portal.status,200);
 assert.ok(portal.headers.get('content-security-policy')?.includes('frame-ancestors'));
 assert.ok((await portal.text()).includes('SHANX13'));
});
test('owner enrolls customer, customer cannot read sibling or owner usage',async()=>{
 const db=fakeDb(),e=env(db);
 const create=await handleRequest(request('/api/admin/accounts',testJWT,'POST',{email:'customer@example.test'}),e);
 assert.equal(create.status,201);
 const created=await create.json();
 db.rows.push({event_id:'owner1',tenant_id:'owner',device_id:'monster',kind:'mcp_call',outcome:'completed',units:99,created_at:'2026-11-22'});
 db.rows.push({event_id:'cust1',tenant_id:created.tenant_id,device_id:'testpc',kind:'mcp_call',outcome:'completed',units:4,created_at:'2026-11-22'});
 const customerJwt=await signedJWT(claims({email:'customer@example.test'}));
 const data=await (await handleRequest(request('/api/usage',customerJwt),e)).json();
 assert.deepEqual(data.total,{requests:1,units:4,devices:1});
 assert.equal(data.events[0].device_id,'testpc');
 const adminDenied=await handleRequest(request('/api/admin/accounts',customerJwt),e);
 assert.equal(adminDenied.status,404);
});
test('agent events authenticate, deduplicate and revoke',async()=>{
 const db=fakeDb(),e=env(db);
 const created=await (await handleRequest(request('/api/admin/agents',testJWT,'POST',{tenant_id:'owner',device_id:'test-machine'}),e)).json();
 assert.ok(created.one_time_token.length>=96);
 assert.equal(db.agents[0].token_hash,await sha256(created.one_time_token));
 assert.equal(db.agents[0].token_hash.includes(created.one_time_token),false);
 const body={event_id:'mcp-event-00001',kind:'mcp_call',outcome:'completed',units:3};
 const send=()=>handleRequest(request('/api/agent/events',null,'POST',body,{authorization:'Bearer '+created.one_time_token}),e);
 assert.equal((await (await send()).json()).stored,true);
 assert.equal((await (await send()).json()).duplicate,true);
 assert.equal(db.rows.length,1);
 const forged=await handleRequest(request('/api/agent/events',null,'POST',body,{authorization:'Bearer '+'a'.repeat(96)}),e);
 assert.equal(forged.status,401);
 const revoke=await handleRequest(request('/api/admin/agents/revoke',testJWT,'POST',{agent_id:created.agent_id}),e);
 assert.equal((await revoke.json()).revoked,true);
 assert.equal((await send()).status,401);
});
test('explicit tenant validation prevents unknown customer enrollment',async()=>{
 const db=fakeDb(),e=env(db);
 const r=await handleRequest(request('/api/admin/agents',testJWT,'POST',{tenant_id:'some-unknown-tenant',device_id:'testpc'}),e);
 assert.equal(r.status,404);
});
test('no endpoint accepts a remote execution command',async()=>{
 const e=env(fakeDb());
 for(const path of ['/api/execute','/mcp','/api/command','/api/write-file']){
   const r=await handleRequest(request(path,testJWT,'POST',{command:'calc.exe'}),e);
   assert.equal(r.status,404,path);
 }
});
