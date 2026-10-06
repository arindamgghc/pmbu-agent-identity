import {readFileSync, mkdirSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const state = JSON.parse(readFileSync(path.join(process.env.PMBU_DATA_DIR || path.join(root,'data'),'state.json'),'utf8'));
const base = process.env.PMBU_URL || 'http://127.0.0.1:4180';
async function api(route, body, key, expected=200) {
  const response=await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${key}`},body:JSON.stringify(body)});
  const result=await response.json();
  if (response.status !== expected) throw new Error(`${route}: expected ${expected}, received ${response.status}: ${JSON.stringify(result)}`);
  return result;
}
const results = [];
for (const context of ['access','edge','enterprise']) {
  // Exercise the public HTTP contract with separate administrator, workload and gateway credentials.
  const actors={};
  for (const profile of ['recipe','travel','health','security']) {
    const enrollment=await api('/v1/admin/agents',{name:`${profile} HTTP demo`,deviceId:`local-${profile}-device`,profile},state.adminKey,201);
    const identity=await api('/v1/identities',{agentId:enrollment.agent.id},enrollment.enrollmentToken,201);
    actors[profile]={agentId:enrollment.agent.id,identity};
  }
  const inputs=[['recipe','recipe_fetch'],['health','model_update'],['travel','booking'],['health','health_alert'],['security','security_alert']];
  const jobs=[];
  for (const [profile,operation] of inputs) {
    const flowId=`http-${context}-${profile}-${operation}`;
    const grant=await api('/v1/activities',{operation,context,flowId},actors[profile].identity.token,201);
    jobs.push({token:grant.token,context,flowId});
  }
  const escalation=await api('/v1/activities',{operation:'health_alert',context,flowId:'escalation'},actors.recipe.identity.token,403);
  const mismatch=await api('/v1/gateway/evaluate',{...jobs[3],flowId:'wrong-flow'},state.gatewayKey,403);
  await api(`/v1/admin/agents/${actors.security.agentId}/status`,{status:'revoked'},state.adminKey);
  await api('/v1/gateway/feedback',{agentId:actors.recipe.agentId,kind:'observation',detail:'HTTP demo observed background recipe traffic'},state.gatewayKey,202);
  const result={context,...await api('/v1/gateway/dispatch',{jobs},state.gatewayKey),attempts:[
    {name:'Recipe agent requests health_alert',blocked:true,reason:escalation.error},
    {name:'Activity used on a different flow',blocked:true,reason:mismatch.error}
  ]};
  results.push(result);
  console.log(`\n${context}: ${result.mode}`);
  console.table(result.dispatched.map(d=>({order:d.dispatchOrder,operation:d.operation,priority:d.trafficClass,dscp:d.dscp})));
  console.log('Rejected:', result.denied.map(d=>d.reason).join('; '));
  console.log('Negative checks:', result.attempts);
}
mkdirSync(path.join(root,'artifacts'),{recursive:true});
writeFileSync(path.join(root,'artifacts','demo-results.json'),JSON.stringify({recordedAt:new Date().toISOString(),results},null,2));
console.log('\nSaved artifacts/demo-results.json (no credentials or bearer tokens).');
