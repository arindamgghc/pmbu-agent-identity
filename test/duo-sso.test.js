import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {IdentityService} from '../identity.js';
import {Foundation,EXCHANGE,JWT_TYPE,RAR_TYPE} from '../rar.js';
import {DuoSso,createDuoOidcProvider} from '../duo-sso.js';
import {createServer} from '../server.js';

function fixture(){
 const issuer='https://sso-test.example/oidc/hackfest',clientId='test-client';
 const keys=generateKeyPairSync('rsa',{modulusLength:2048});
 const jwk={...keys.publicKey.export({format:'jwk'}),kid:'test-key',alg:'RS256',use:'sig'};
 const state={overrides:{},invalidSignature:false,tokenCalls:0,params:undefined};
 const customFetch=async(input,options)=>{
  const url=new URL(input instanceof Request?input.url:input);
  let result;
  if(url.pathname.includes('.well-known'))result={issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/jwks',response_types_supported:['code'],subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],code_challenge_methods_supported:['S256']};
  else if(url.pathname.endsWith('/jwks'))result={keys:[jwk]};
  else if(url.pathname.endsWith('/token')){
   state.tokenCalls++;
   const body=new URLSearchParams(options.body);assert.equal(body.get('redirect_uri'),'https://identity.example/duo/sso/callback');
   assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'),state.params.get('code_challenge'));
   const now=Math.floor(Date.now()/1000);
   const claims={iss:issuer,sub:'owner-123',aud:clientId,iat:now,exp:now+300,auth_time:now,email:'owner@cisco.com',amr:['pwd','mfa','pop','user'],nonce:state.params.get('nonce'),...state.overrides};
   const head=Buffer.from(JSON.stringify({alg:'RS256',kid:'test-key'})).toString('base64url'),payload=Buffer.from(JSON.stringify(claims)).toString('base64url');
   const signature=sign('sha256',Buffer.from(head+'.'+payload),keys.privateKey).toString('base64url');
   result={access_token:'test-access-token',token_type:'Bearer',expires_in:300,id_token:head+'.'+payload+'.'+(state.invalidSignature?'AAAA':signature)};
  }else throw new Error('Unexpected OIDC request');
  return new Response(JSON.stringify(result),{status:200,headers:{'Content-Type':'application/json'}});
 };
 const service=new IdentityService();const foundation=new Foundation(service,{duoMode:'oidc'});
 const provider=createDuoOidcProvider({issuer,clientId,clientSecret:'test-secret',redirectUri:'https://identity.example/duo/sso/callback',customFetch});
 const sso=new DuoSso(foundation,provider);foundation.sso=sso;
 const agent=service.register({name:'Security',deviceId:'ue',profile:'security',owner:'owner@cisco.com'});
 const identity=service.issueIdentity(agent.enrollmentToken,{agentId:agent.agent.id,agentIp:'192.0.2.1',agentPort:45001});
 async function begin(){
  const request=sso.request(identity.token,{agentIp:'192.0.2.1',agentPort:45001});
  const ticket=new URL(request.loginUrl).searchParams.get('request');
  const redirect=await sso.start(ticket);state.params=new URL(redirect.location).searchParams;
  const callback=new URL(provider.redirectUri);callback.searchParams.set('code','test-code');callback.searchParams.set('state',state.params.get('state'));
  return {request,ticket,redirect,callback,cookie:redirect.cookie.split(';')[0]};
 }
 function tokenBody(pushId){return {grant_type:EXCHANGE,subject_token_type:JWT_TYPE,subject_token:identity.token,audience:'pmbu-pcf-adapter',duo_approval_id:pushId,
  authorization_details:[{type:RAR_TYPE,operation:'security_alert',network_context:'access',flow_id:'sso-alert',subscriber_id:'demo-sub',pdu_session_id:'demo-pdu',flow:{src_ip:'192.0.2.1',src_port:45001,dst_ip:'192.0.2.2',dst_port:443,protocol:'tcp'}}]};}
 return {state,service,foundation,sso,provider,identity,agent,begin,tokenBody};
}

test('validated OIDC owner login with MFA approves only its agent session and permits activity authorization',async()=>{
 const x=fixture(),flow=await x.begin();
 assert.equal(x.state.params.get('scope'),'openid email');assert.equal(x.state.params.get('code_challenge_method'),'S256');
 assert.match(flow.redirect.cookie,/HttpOnly; Secure; SameSite=Lax/);
 assert.throws(()=>x.foundation.issue(x.tokenBody(flow.request.id)),e=>e.status===403);
 const result=await x.sso.callback(flow.callback,flow.cookie);assert.equal(result.status,'approved');assert.equal(result.mfaVerified,true);
 const grant=x.foundation.introspect(x.foundation.issue(x.tokenBody(flow.request.id)).access_token);
 assert.equal(grant.active,true);assert.equal(grant.approval_source,'oidc');assert.equal(grant.owner_subject,'owner-123');assert.equal(grant.mfa_verified,true);
 await assert.rejects(()=>x.sso.callback(flow.callback,flow.cookie),e=>e.status===401);
 await assert.rejects(()=>x.sso.start(flow.ticket),e=>e.status===401);
 assert.ok(!JSON.stringify(x.service.state).includes('test-access-token'));
});

test('OIDC rejects invalid signatures, audience, issuer, nonce and expired ID tokens',async()=>{
 for(const change of [{signature:true},{aud:'other'},{iss:'https://wrong.example'},{nonce:'wrong'},{exp:1}]){
  const x=fixture(),flow=await x.begin();if(change.signature)x.state.invalidSignature=true;else x.state.overrides=change;
  await assert.rejects(()=>x.sso.callback(flow.callback,flow.cookie),e=>e.status===401);
  assert.equal(x.foundation.state.pushes[flow.request.id].status,'denied');
  assert.throws(()=>x.foundation.issue(x.tokenBody(flow.request.id)),e=>e.status===403);
 }
});

test('a different owner or MFA bypass cannot approve an agent',async()=>{
 for(const claims of [{email:'other@cisco.com'},{email:null},{amr:['pwd']},{amr:undefined}]){
  const x=fixture(),flow=await x.begin();x.state.overrides=claims;
  let pcfCalls=0;x.foundation.pcfClient={apply:async()=>{pcfCalls++;}};
  await assert.rejects(()=>x.sso.callback(flow.callback,flow.cookie),e=>e.status===403);
  assert.equal(x.foundation.state.pushes[flow.request.id].status,'denied');
  await assert.rejects(()=>x.foundation.issueWithPcf(x.tokenBody(flow.request.id)),e=>e.status===403);assert.equal(pcfCalls,0);
 }
});

test('browser binding, single-use state, denial, expiry and owner changes fail closed',async()=>{
 for(const mode of ['cookie','denied','expiry','owner']){
  const x=fixture(),flow=await x.begin();
  if(mode==='denied'){flow.callback.searchParams.delete('code');flow.callback.searchParams.set('error','access_denied');}
  if(mode==='expiry')x.foundation.state.pushes[flow.request.id].expiresAt=0;
  if(mode==='owner')x.service.setOwner(x.agent.agent.id,'new-owner@cisco.com');
  await assert.rejects(()=>x.sso.callback(flow.callback,mode==='cookie'?'':flow.cookie));
  assert.notEqual(x.foundation.state.pushes[flow.request.id].status,'approved');
  if(mode!=='denied')assert.equal(x.state.tokenCalls,0);
 }
});

test('real mode prevents simulator approval, and SSO requires an administrator-assigned owner email',()=>{
 const x=fixture();const request=x.sso.request(x.identity.token);
 assert.throws(()=>x.foundation.decide(request.id,'approved'),e=>e.status===403);
 x.service.state.agents[x.agent.agent.id].owner='hackfest-team';
 assert.throws(()=>x.sso.request(x.identity.token),e=>e.status===400);
});

test('HTTP OIDC endpoints create, redirect, approve and expose session-bound status without simulator bypass',async t=>{
 const x=fixture();const server=createServer(x.service,{foundation:x.foundation});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base='http://127.0.0.1:'+server.address().port;
 const headers={'Content-Type':'application/json',Authorization:'Bearer '+x.identity.token};
 const response=await fetch(base+'/duo/sso/requests',{method:'POST',headers,body:JSON.stringify({agentIp:'192.0.2.1',agentPort:45001})});assert.equal(response.status,201);const request=await response.json();
 const start=await fetch(base+new URL(request.loginUrl).pathname+new URL(request.loginUrl).search,{redirect:'manual'});assert.equal(start.status,302);x.state.params=new URL(start.headers.get('location')).searchParams;
 const callback=new URL(base+'/duo/sso/callback');callback.searchParams.set('code','test-code');callback.searchParams.set('state',x.state.params.get('state'));
 const approved=await fetch(callback,{headers:{Cookie:start.headers.get('set-cookie').split(';')[0]}});assert.equal(approved.status,200);assert.equal((await approved.json()).status,'approved');
 const status=await fetch(base+'/duo/sso/requests/'+request.id,{headers});assert.equal((await status.json()).status,'approved');
 const noAuth=await fetch(base+'/duo/sso/requests/'+request.id);assert.equal(noAuth.status,401);
 const simulator=await fetch(base+'/duo/admin/decide',{method:'POST',headers:{...headers,Authorization:'Bearer '+x.service.state.adminKey},body:JSON.stringify({push_id:request.id,status:'approved'})});assert.equal(simulator.status,403);
 const oldPush=await fetch(base+'/duo/push',{method:'POST',headers,body:'{}'});assert.equal(oldPush.status,403);
 const ownerUrl=base+'/v1/admin/agents/'+x.agent.agent.id+'/owner';
 const unauthorized=await fetch(ownerUrl,{method:'POST',headers,body:JSON.stringify({owner:'other@cisco.com'})});assert.equal(unauthorized.status,401);
 const changed=await fetch(ownerUrl,{method:'POST',headers:{...headers,Authorization:'Bearer '+x.service.state.adminKey},body:JSON.stringify({owner:'other@cisco.com'})});assert.equal(changed.status,200);
 const revoked=await fetch(base+'/duo/sso/requests/'+request.id,{headers});assert.equal(revoked.status,401);
});

test('owner change revokes existing identities and approvals cannot be borrowed by another session',async()=>{
 const x=fixture(),flow=await x.begin();await x.sso.callback(flow.callback,flow.cookie);
 const next=x.service.register({name:'Other',deviceId:'ue',profile:'security',owner:'owner@cisco.com'});const identity=x.service.issueIdentity(next.enrollmentToken,{agentId:next.agent.id,agentIp:'192.0.2.1',agentPort:45001});
 assert.throws(()=>x.foundation.issue({...x.tokenBody(flow.request.id),subject_token:identity.token}),e=>e.status===403);
 x.service.setOwner(x.agent.agent.id,'new-owner@cisco.com');assert.throws(()=>x.foundation.issue(x.tokenBody(flow.request.id)),e=>e.status===401);
});
