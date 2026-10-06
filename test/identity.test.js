import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync, statSync, readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {IdentityService} from '../identity.js';
import {dispatch,runDemo} from '../gateway.js';
import {createServer} from '../server.js';

function fixture(profile='health', ttlSeconds=600) {
  let now=1000;
  const service=new IdentityService({clock:()=>now});
  const enrolled=service.register({name:'Test agent', deviceId:'pi-01', profile});
  const identity=service.issueIdentity(enrolled.enrollmentToken,{agentId:enrolled.agent.id,ttlSeconds});
  const flow={context:'access',flowId:'test-flow'};
  const grant=service.issueActivity(identity.token,{operation:profile==='recipe'?'recipe_fetch':'health_alert',...flow});
  return {service,enrolled,identity,grant,flow,advance:seconds=>{now+=seconds;}};
}
const denies=(fn,status)=>assert.throws(fn,error=>error.status===status);
test('same identity has background and critical activity grants',()=>{
  const f=fixture();const update=f.service.issueActivity(f.identity.token,{operation:'model_update',...f.flow});
  assert.equal(f.service.evaluate(update.token,f.flow).trafficClass,'background');
  assert.equal(f.service.evaluate(f.grant.token,f.flow).trafficClass,'critical');
});
test('recipe identity cannot request a critical health operation',()=>{
  const f=fixture('recipe');denies(()=>f.service.issueActivity(f.identity.token,{operation:'health_alert',...f.flow}),403);
});
test('self-asserted priority and profile are ignored',()=>{
  const f=fixture('recipe');const grant=f.service.issueActivity(f.identity.token,{operation:'recipe_fetch',...f.flow,profile:'health',trafficClass:'critical'});
  assert.equal(f.service.evaluate(grant.token,f.flow).trafficClass,'background');
});
test('bootstrap is one-time and subject-scoped',()=>{
  const f=fixture();denies(()=>f.service.issueIdentity(f.enrolled.enrollmentToken,{agentId:f.enrolled.agent.id}),401);
  const other=f.service.register({name:'other',deviceId:'pi-02',profile:'health'});
  denies(()=>f.service.issueIdentity(other.enrollmentToken,{agentId:f.enrolled.agent.id}),401);
});
test('bootstrap expires at five minutes',()=>{
  let now=1;const service=new IdentityService({clock:()=>now});
  const enrollment=service.register({name:'test',deviceId:'pi',profile:'health'});now+=300;
  denies(()=>service.issueIdentity(enrollment.enrollmentToken,{agentId:enrollment.agent.id}),401);
});
test('signature tampering, malformed token and algorithm substitution fail',()=>{
  const f=fixture();const parts=f.grant.token.split('.');
  const claims=JSON.parse(Buffer.from(parts[1],'base64url'));claims.flowId='forged';
  parts[1]=Buffer.from(JSON.stringify(claims)).toString('base64url');
  denies(()=>f.service.evaluate(parts.join('.'),f.flow),401);
  denies(()=>f.service.evaluate('not-a-token',f.flow),401);
  parts[0]=Buffer.from(JSON.stringify({alg:'none'})).toString('base64url');
  denies(()=>f.service.evaluate(parts.join('.'),f.flow),401);
});
test('wrong token purpose, flow and context fail',()=>{
  const f=fixture();denies(()=>f.service.evaluate(f.identity.token,f.flow),401);
  denies(()=>f.service.issueActivity(f.grant.token,{operation:'health_alert',...f.flow}),401);
  denies(()=>f.service.evaluate(f.grant.token,{...f.flow,flowId:'another'}),403);
  denies(()=>f.service.evaluate(f.grant.token,{...f.flow,context:'enterprise'}),403);
});
test('identity expiration clamps grants and rejects at boundary',()=>{
  const f=fixture('health',10);assert.equal(f.grant.expiresAt,f.identity.expiresAt);f.advance(10);
  denies(()=>f.service.evaluate(f.grant.token,f.flow),401);
  denies(()=>f.service.renew(f.identity.token,{}),401);
});
test('activity expires before a longer-lived identity',()=>{
  const f=fixture();f.advance(120);denies(()=>f.service.evaluate(f.grant.token,f.flow),401);
  assert.equal(f.service.validate(f.identity.token,'identity').agent.id,f.enrolled.agent.id);
});
test('renewal replaces old identity expiry and does not extend existing activity',()=>{
  const f=fixture();f.advance(30);const renewed=f.service.renew(f.identity.token,{});
  assert.ok(renewed.expiresAt>f.identity.expiresAt);denies(()=>f.service.renew(f.identity.token,{}),401);
  f.advance(90);denies(()=>f.service.evaluate(f.grant.token,f.flow),401);
  assert.equal(f.service.validate(renewed.token,'identity').session.id,f.identity.sessionId);
});
test('revocation is immediate and terminal',()=>{
  const f=fixture();f.service.setStatus(f.enrolled.agent.id,'revoked');
  denies(()=>f.service.evaluate(f.grant.token,f.flow),401);
  denies(()=>f.service.issueActivity(f.identity.token,{operation:'health_alert',...f.flow}),401);
  denies(()=>f.service.setStatus(f.enrolled.agent.id,'active'),409);
});
test('suspension followed by reactivation does not revive old credentials',()=>{
  const f=fixture();f.service.setStatus(f.enrolled.agent.id,'suspended');f.service.setStatus(f.enrolled.agent.id,'active');
  denies(()=>f.service.evaluate(f.grant.token,f.flow),401);
});
test('activity end affects only that activity; identity end affects all',()=>{
  const f=fixture();f.service.endActivity(f.grant.token);denies(()=>f.service.evaluate(f.grant.token,f.flow),401);
  const next=f.service.issueActivity(f.identity.token,{operation:'model_update',...f.flow});
  f.service.endIdentity(f.identity.token);denies(()=>f.service.evaluate(next.token,f.flow),401);
});
test('current policy overrides existing grants; removing an operation denies',()=>{
  const f=fixture();const rules=structuredClone(f.service.state.policy.rules);rules.health.health_alert='background';
  f.service.replaceRules(rules);const decision=f.service.evaluate(f.grant.token,f.flow);
  assert.equal(decision.trafficClass,'background');assert.equal(decision.policyVersion,2);
  delete rules.health.health_alert;f.service.replaceRules(rules);denies(()=>f.service.evaluate(f.grant.token,f.flow),403);
});
test('invalid TTLs, profiles, classes and contexts fail',()=>{
  const f=fixture();for (const ttlSeconds of [0,-1,1.5,601,'120']) denies(()=>f.service.renew(f.identity.token,{ttlSeconds}),400);
  denies(()=>f.service.issueActivity(f.identity.token,{operation:'health_alert',...f.flow,context:'invalid'}),400);
  denies(()=>f.service.register({name:'x',deviceId:'x',profile:'__proto__'}),400);
  const rules=structuredClone(f.service.state.policy.rules);rules.health.health_alert='root';denies(()=>f.service.replaceRules(rules),400);
});
test('feedback records observations but cannot grant or suspend identity',()=>{
  const f=fixture();const result=f.service.feedback({agentId:f.enrolled.agent.id,kind:'policy_violation',detail:'unexpected transfer'});
  assert.equal(result.action,'administrator review');assert.equal(result.status,'active');
  assert.equal(f.service.evaluate(f.grant.token,f.flow).trafficClass,'critical');
});
test('scheduler orders critical first and preserves FIFO within class',()=>{
  const f=fixture();const update=f.service.issueActivity(f.identity.token,{operation:'model_update',...f.flow});
  const result=dispatch(f.service,[{token:update.token,...f.flow},{token:f.grant.token,...f.flow},{token:f.grant.token,...f.flow}]);
  assert.deepEqual(result.dispatched.map(d=>d.arrival),[1,2,0]);assert.equal(result.denied.length,0);
});
test('all three network contexts demonstrate priority, escalation denial and revocation',()=>{
  for (const context of ['access','edge','enterprise']) {
    const result=runDemo(new IdentityService(),context);
    assert.deepEqual(result.dispatched.map(d=>d.operation),['health_alert','booking','recipe_fetch','model_update']);
    assert.equal(result.denied.length,1);assert.ok(result.attempts.every(a=>a.blocked));
    assert.equal(result.dispatched[0].agentId,result.dispatched[3].agentId);
  }
});
test('persistent issuer preserves revocation and keys across restart without leaking tokens to audit',()=>{
  const directory=mkdtempSync(path.join(tmpdir(),'pmbu-test-'));
  try {
    const service=new IdentityService({directory});const enrolled=service.register({name:'test',deviceId:'pi',profile:'health'});
    const identity=service.issueIdentity(enrolled.enrollmentToken,{agentId:enrolled.agent.id});
    service.setStatus(enrolled.agent.id,'revoked');const restart=new IdentityService({directory});
    assert.equal(restart.state.publicKey,service.state.publicKey);denies(()=>restart.validate(identity.token,'identity'),401);
    assert.equal(statSync(path.join(directory,'state.json')).mode&0o777,0o600);
    const audit=JSON.stringify(restart.snapshot());assert.ok(!audit.includes(identity.token));assert.ok(!audit.includes(enrolled.enrollmentToken));
    assert.ok(!audit.includes(service.state.adminKey));assert.ok(!audit.includes(service.state.privateKey));
  } finally {rmSync(directory,{recursive:true,force:true});}
});
test('HTTP API enforces role separation and covers enrollment → activity → gateway',async t=>{
  const service=new IdentityService();const server=createServer(service);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const base=`http://127.0.0.1:${server.address().port}`;
  const call=async(route,body,key,method=body?'POST':'GET')=>{
    const response=await fetch(base+route,{method,headers:{'Content-Type':'application/json',Authorization:`Bearer ${key||'none'}`},body:body?JSON.stringify(body):undefined});
    return {status:response.status,body:await response.json()};
  };
  assert.equal((await call('/v1/admin/snapshot')).status,401);
  assert.equal((await call('/v1/admin/snapshot',undefined,service.state.gatewayKey)).status,401);
  const enrolled=await call('/v1/admin/agents',{name:'health',deviceId:'pi',profile:'health'},service.state.adminKey);assert.equal(enrolled.status,201);
  const identity=await call('/v1/identities',{agentId:enrolled.body.agent.id},enrolled.body.enrollmentToken);assert.equal(identity.status,201);
  const grant=await call('/v1/activities',{operation:'health_alert',context:'edge',flowId:'f1'},identity.body.token);assert.equal(grant.status,201);
  const evaluation={token:grant.body.token,context:'edge',flowId:'f1'};
  assert.equal((await call('/v1/gateway/evaluate',evaluation,service.state.adminKey)).status,401);
  const allowed=await call('/v1/gateway/evaluate',evaluation,service.state.gatewayKey);assert.equal(allowed.body.trafficClass,'critical');
  await call(`/v1/admin/agents/${enrolled.body.agent.id}/status`,{status:'revoked'},service.state.adminKey);
  assert.equal((await call('/v1/gateway/evaluate',evaluation,service.state.gatewayKey)).status,401);
  assert.equal((await call('/v1/admin/policy',{rules:{}},service.state.adminKey,'PUT')).status,400);
  const invalid=await fetch(base+'/v1/admin/agents',{method:'POST',headers:{Authorization:`Bearer ${service.state.adminKey}`,'Content-Type':'application/json'},body:'{bad'});
  assert.equal(invalid.status,400);
});
