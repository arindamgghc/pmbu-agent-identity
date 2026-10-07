import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http2';
import {IdentityService} from '../identity.js';
import {Foundation,EXCHANGE,JWT_TYPE,RAR_TYPE} from '../rar.js';
import {PcfClient} from '../pcf.js';

async function fixture(t, status=200, stall=false){
 const requests=[];const server=createServer();
 server.on('stream',(stream,headers)=>{let body='';stream.on('error',()=>{});stream.on('data',chunk=>body+=chunk);stream.on('end',()=>{requests.push({headers,body:JSON.parse(body)});if(!stall){stream.respond({':status':status});stream.end('{}');}});});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const client=new PcfClient({endpoint:'http://127.0.0.1:'+server.address().port+'/api/policy',policies:{background:'downgrade'},timeoutMs:stall?100:5000});
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
