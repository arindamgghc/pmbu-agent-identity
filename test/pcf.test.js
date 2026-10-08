import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http2';
import {IdentityService} from '../identity.js';
import {Foundation,EXCHANGE,JWT_TYPE,RAR_TYPE} from '../rar.js';
import {PcfClient} from '../pcf.js';

async function fixture(t, status=200, stall=false, policies={background:'downgrade'}){
 const requests=[];const server=createServer();
 server.on('stream',(stream,headers)=>{let body='';stream.on('error',()=>{});stream.on('data',chunk=>body+=chunk);stream.on('end',()=>{requests.push({headers,body:JSON.parse(body)});if(!stall){stream.respond({':status':status});stream.end('{}');}});});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const client=new PcfClient({endpoint:'http://127.0.0.1:'+server.address().port+'/api/policy',policies,timeoutMs:stall?100:5000});
 const s=new IdentityService();const f=new Foundation(s,{pcfClient:client});const e=s.register({name:'Security',deviceId:'ue',profile:'security'});
 const i=s.issueIdentity(e.enrollmentToken,{agentId:e.agent.id,agentIp:'192.0.2.1',agentPort:1234});const push=f.push(i.token);
 const detail={type:RAR_TYPE,operation:'model_update',network_context:'access',flow_id:'f',subscriber_id:'sub',pdu_session_id:'pdu',flow:{src_ip:'192.0.2.1',src_port:1234,dst_ip:'192.0.2.2',dst_port:443,protocol:'tcp'}};
 const body={grant_type:EXCHANGE,subject_token_type:JWT_TYPE,subject_token:i.token,audience:'pmbu-pcf-adapter',duo_approval_id:push.id,authorization_details:[detail]};
 return {requests,s,f,push,body};
}
test('HTTP/2 PCF call follows successful approval and activity authorization with exact agreed payload',async t=>{
 const x=await fixture(t);await assert.rejects(()=>x.f.issueWithPcf(x.body),e=>e.status===403);assert.equal(x.requests.length,0);
 x.f.decide(x.push.id,'approved');const result=await x.f.issueWithPcf(x.body);
 assert.deepEqual(x.requests[0].body,{agentIP:'192.0.2.1',agentPort:'1234',policy:'downgrade'});assert.equal(x.requests[0].headers[':path'],'/api/policy');assert.equal(result.pcf.status,'api_accepted');assert.equal(result.pcf.networkEnforcementVerified,false);assert.equal(x.f.introspect(result.access_token).active,true);
 await assert.rejects(()=>x.f.issueWithPcf({...x.body,authorization_details:[{...x.body.authorization_details[0],qos_tier:'critical'}]}),e=>e.status===403);assert.equal(x.requests.length,1);
});
test('unconfirmed priority mapping never sends a PCF request or leaves an active token',async t=>{
 const x=await fixture(t);x.f.decide(x.push.id,'approved');await assert.rejects(()=>x.f.issueWithPcf({...x.body,authorization_details:[{...x.body.authorization_details[0],operation:'security_alert'}]}),e=>e.status===503);
 assert.equal(x.requests.length,0);assert.equal(Object.keys(x.f.state.tokens).length,0);
});
test('PCF rejection or timeout returns failure without leaving an active entitlement',async t=>{
 for(const [status,stall] of [[500,false],[200,true]]){
  const x=await fixture(t,status,stall);x.f.decide(x.push.id,'approved');await assert.rejects(()=>x.f.issueWithPcf(x.body),e=>e.status===(stall?504:502));assert.equal(Object.keys(x.f.state.tokens).length,0);
 }
});
test('same approved security agent requests downgrade for updates and boost for alerts',async t=>{
 const x=await fixture(t,200,false,{background:'downgrade',interactive:'boost',critical:'boost'});x.f.decide(x.push.id,'approved');
 const update=await x.f.issueWithPcf(x.body);
 const alert=await x.f.issueWithPcf({...x.body,authorization_details:[{...x.body.authorization_details[0],operation:'security_alert'}]});
 assert.equal(update.pcf.policy,'downgrade');assert.equal(alert.pcf.policy,'boost');
 assert.deepEqual(x.requests.map(r=>r.body),[
  {agentIP:'192.0.2.1',agentPort:'1234',policy:'downgrade'},
  {agentIP:'192.0.2.1',agentPort:'1234',policy:'boost'}
 ]);
 const travel=x.s.register({name:'Travel',deviceId:'ue',profile:'travel'});const identity=x.s.issueIdentity(travel.enrollmentToken,{agentId:travel.agent.id,agentIp:'192.0.2.1',agentPort:1234});const push=x.f.push(identity.token);x.f.decide(push.id,'approved');
 const booking=await x.f.issueWithPcf({...x.body,subject_token:identity.token,duo_approval_id:push.id,authorization_details:[{...x.body.authorization_details[0],operation:'booking'}]});assert.equal(booking.pcf.policy,'boost');assert.equal(x.requests[2].body.policy,'boost');
 assert.equal(x.f.introspect(alert.access_token).qos_tier,'critical');
});
test('PCF mapping rejects instructions outside the confirmed downgrade/boost contract',()=>{
 assert.throws(()=>new PcfClient({endpoint:'http://127.0.0.1:18091/api/policy',policies:{critical:'upgrade'}}),e=>e.status===400);
});

test('dashboard activity buttons require admin, matching identity and Duo approval before applying current policy',async t=>{
 const {createServer:dashboard}=await import('../server.js');
 const x=await fixture(t,200,false,{background:'downgrade',interactive:'boost',critical:'boost'});
 const server=dashboard(x.s,{foundation:x.f});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base='http://127.0.0.1:'+server.address().port;
 const agentId=x.s.validate(x.body.subject_token,'identity').agent.id;
 const request={action:'alert',identityToken:x.body.subject_token,approvalId:x.push.id,context:'access',flowId:'lab-flow',
  destinationIp:'192.0.2.2',destinationPort:443,protocol:'tcp',subscriberId:'sub',pduSessionId:'pdu'};
 const call=(body=request,key=x.s.state.adminKey,id=agentId)=>fetch(base+'/v1/admin/agents/'+id+'/activity',{
  method:'POST',headers:{Authorization:'Bearer '+key,'Content-Type':'application/json'},body:JSON.stringify(body)});
 assert.equal((await call(request,'wrong')).status,401);
 assert.equal((await call()).status,403);assert.equal(x.requests.length,0);
 x.f.decide(x.push.id,'approved');
 assert.equal((await call(request,x.s.state.adminKey,'different-agent')).status,403);
 assert.equal((await call({...request,action:'boost'})).status,400);assert.equal(x.requests.length,0);
 const alert=await call();assert.equal(alert.status,200);assert.equal((await alert.json()).pcf.policy,'boost');
 const update=await call({...request,action:'background'});assert.equal(update.status,200);assert.equal((await update.json()).pcf.policy,'downgrade');
 assert.deepEqual(x.requests.map(r=>r.body),[{agentIP:'192.0.2.1',agentPort:'1234',policy:'boost'},{agentIP:'192.0.2.1',agentPort:'1234',policy:'downgrade'}]);
 x.s.replaceRules({...x.s.state.policy.rules,security:{model_update:'background',security_alert:'background'}});
 assert.equal((await call()).status,200);assert.equal(x.requests.at(-1).body.policy,'downgrade');
 x.s.endIdentity(x.body.subject_token);
 assert.equal((await call()).status,401);assert.equal(x.requests.length,3);
});
