import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import path from 'node:path';
import {IdentityService} from '../identity.js';import {Foundation,RAR_TYPE,EXCHANGE,JWT_TYPE} from '../rar.js';import {createServer} from '../server.js';
function fixture(){let now=1000;const s=new IdentityService({clock:()=>now});const f=new Foundation(s);
 const e=s.register({name:'Security',deviceId:'desk',profile:'security'});const identity=s.issueIdentity(e.enrollmentToken,{agentId:e.agent.id});
 const p=f.push(identity.token);const d={type:RAR_TYPE,operation:'security_alert',network_context:'access',flow_id:'f1',subscriber_id:'demo-sub',pdu_session_id:'demo-pdu',flow:{src_ip:'192.0.2.1',dst_ip:'192.0.2.2',src_port:12000,dst_port:443,protocol:'tcp'}};
 const b={grant_type:EXCHANGE,subject_token:identity.token,subject_token_type:JWT_TYPE,audience:'pmbu-pcf-adapter',duo_approval_id:p.id,authorization_details:[d]};
 return {s,f,e,identity,p,d,b,advance:n=>{now+=n;}};}
const denies=(fn,status)=>assert.throws(fn,e=>e.status===status);
test('pending and denied Duo pushes cannot issue entitlements',()=>{const x=fixture();denies(()=>x.f.issue(x.b),403);x.f.decide(x.p.id,'denied');denies(()=>x.f.issue(x.b),403);denies(()=>x.f.decide(x.p.id,'approved'),409);});
test('approved push yields signed audience-scoped RAR details with policy QoS',()=>{const x=fixture();x.f.decide(x.p.id,'approved');const result=x.f.issue(x.b);const c=x.f.introspect(result.access_token);assert.equal(c.active,true);assert.equal(c['5qi'],7);assert.equal(c.dscp,46);assert.equal(c.qos_tier,'critical');assert.equal(c.enforcement,'dry_run_only');assert.deepEqual(result.authorization_details,c.authorization_details);});
test('same agent can obtain background grant but cannot boost it',()=>{const x=fixture();x.f.decide(x.p.id,'approved');const b={...x.b,authorization_details:[{...x.d,operation:'model_update'}]};assert.equal(x.f.issue(b).authorization_details[0].qos_tier,'background');for(const changes of [{qos_tier:'critical'},{'5qi':1},{dscp:46}])denies(()=>x.f.issue({...b,authorization_details:[{...b.authorization_details[0],...changes}]}),403);});
test('invalid types, malformed authorization_details and missing flow fail',()=>{const x=fixture();x.f.decide(x.p.id,'approved');for(const d of [[],[{}],[{...x.d,type:'payments'}],[{...x.d,flow:null}],[{...x.d,unexpected:'value'}]])denies(()=>x.f.issue({...x.b,authorization_details:d}),400);denies(()=>x.f.issue({...x.b,authorization_details:'bad'}),400);denies(()=>x.f.issue({...x.b,audience:'another-adapter'}),400);});
test('approval is session-bound and cannot be borrowed by another agent',()=>{const x=fixture();x.f.decide(x.p.id,'approved');const e=x.s.register({name:'another',deviceId:'desk',profile:'security'});const i=x.s.issueIdentity(e.enrollmentToken,{agentId:e.agent.id});denies(()=>x.f.issue({...x.b,subject_token:i.token}),403);});
test('RAR signature tampering, expiry and identity termination fail introspection',()=>{const x=fixture();x.f.decide(x.p.id,'approved');const r=x.f.issue(x.b);const [h,p,s]=r.access_token.split('.');const c=JSON.parse(Buffer.from(p,'base64url'));c.dscp=63;assert.equal(x.f.introspect(h+'.'+Buffer.from(JSON.stringify(c)).toString('base64url')+'.'+s).active,false);x.advance(120);assert.equal(x.f.introspect(r.access_token).active,false);});
test('revocation and policy changes invalidate existing RAR entitlements',()=>{for(const mode of ['revocation','policy']){const x=fixture();x.f.decide(x.p.id,'approved');const r=x.f.issue(x.b);if(mode==='revocation')x.s.setStatus(x.e.agent.id,'revoked');else x.s.replaceRules(structuredClone(x.s.state.policy.rules));assert.equal(x.f.introspect(r.access_token).active,false);}});
test('SPIRE JWT verification uses trusted bundle, audience and admin subject mapping',()=>{
 const x=fixture(),directory=mkdtempSync(path.join(tmpdir(),'pmbu-svid-'));try{
 const pair=generateKeyPairSync('rsa',{modulusLength:2048});const key={...pair.publicKey.export({format:'jwk'}),kid:'test-key',use:'jwt-svid'};
 const bundle=path.join(directory,'bundle.json');writeFileSync(bundle,JSON.stringify({keys:[key]}));const f=new Foundation(x.s,{bundlePath:bundle});
 const subject='spiffe://pmbu.demo/workloads/security';f.bind({agentId:x.e.agent.id,spiffeId:subject});
 const jwt=claims=>{const h=Buffer.from(JSON.stringify({alg:'RS256',kid:'test-key'})).toString('base64url'),p=Buffer.from(JSON.stringify(claims)).toString('base64url');return h+'.'+p+'.'+sign('sha256',Buffer.from(h+'.'+p),pair.privateKey).toString('base64url');};
 const c={sub:subject,aud:['pmbu-rar-issuer'],iat:1000,exp:1100};const result=f.exchangeSvid(jwt(c));assert.equal(result.identitySource,'verified-jwt-svid');assert.equal(result.sourceSpiffeId,subject);
 denies(()=>f.exchangeSvid(jwt({...c,aud:['other']})),401);denies(()=>f.exchangeSvid(jwt({...c,sub:'spiffe://pmbu.demo/unregistered'})),403);denies(()=>f.exchangeSvid(jwt({...c,exp:1000})),401);
 }finally{rmSync(directory,{recursive:true,force:true});}});
test('HTTP form token exchange, client role auth, metadata and introspection',async t=>{
 const x=fixture();x.f.decide(x.p.id,'approved');const server=createServer(x.s,{foundation:x.f});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const base='http://127.0.0.1:'+server.address().port;const basic=id=>'Basic '+Buffer.from(id+':'+x.s.state.gatewayKey).toString('base64');
 const r=await fetch(base+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Authorization:basic('pmbu-agent-client')},body:new URLSearchParams({...x.b,authorization_details:JSON.stringify(x.b.authorization_details)})});assert.equal(r.status,200);const token=(await r.json()).access_token;
 const i=await fetch(base+'/oauth/introspect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Authorization:basic('pmbu-pcf-adapter')},body:new URLSearchParams({token})});assert.equal((await i.json()).active,true);
 const bad=await fetch(base+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(x.b)});assert.equal(bad.status,401);
 const meta=await (await fetch(base+'/.well-known/oauth-authorization-server')).json();assert.deepEqual(meta.authorization_details_types_supported,[RAR_TYPE]);
 const keys=await (await fetch(base+'/.well-known/jwks.json')).json();assert.ok(!JSON.stringify(keys).includes('"d":'));
});
