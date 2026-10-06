import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {EXCHANGE,JWT_TYPE,RAR_TYPE} from '../rar.js';
const base=process.env.PMBU_URL||'http://127.0.0.1:4191';
const state=JSON.parse(readFileSync(process.env.PMBU_STATE_FILE||'foundation-data/state.json','utf8'));
const client=name=>'Basic '+Buffer.from(name+':'+state.gatewayKey).toString('base64');
async function call(route,body,auth,expected=200){
 const r=await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json',Authorization:auth},body:JSON.stringify(body)});
 const data=await r.json();if(r.status!==expected)throw new Error(route+': '+JSON.stringify(data));return data;
}
const admin='Bearer '+state.adminKey;
const enrolled=await call('/v1/admin/agents',{name:'Home security',deviceId:'deskside-assistant',profile:'security',owner:'demo-human'},admin,201);
const identity=await call('/v1/identities',{agentId:enrolled.agent.id},'Bearer '+enrolled.enrollmentToken,201);
const push=await call('/duo/push',{},'Bearer '+identity.token,201);
const details={type:RAR_TYPE,operation:'security_alert',network_context:'access',flow_id:'security-alert-01',subscriber_id:'DEMO-SUBSCRIBER',pdu_session_id:'demo-session-1',
 flow:{src_ip:'192.0.2.10',dst_ip:'192.0.2.20',src_port:45000,dst_port:443,protocol:'tcp'}};
const request={grant_type:EXCHANGE,subject_token:identity.token,subject_token_type:JWT_TYPE,audience:'pmbu-pcf-adapter',duo_approval_id:push.id,authorization_details:[details]};
await call('/oauth/token',request,client('pmbu-agent-client'),403);
await call('/duo/admin/decide',{push_id:push.id,status:'approved'},admin);
const token=await call('/oauth/token',request,client('pmbu-agent-client'));
const positive=await call('/oauth/introspect',{token:token.access_token},client('pmbu-pcf-adapter'));
if(!positive.active)throw new Error('Token inactive');
const claims=JSON.parse(Buffer.from(token.access_token.split('.')[1],'base64url'));
console.log('Signed QoS entitlement:',JSON.stringify(claims.authorization_details,null,2));
const background=await call('/oauth/token',{...request,authorization_details:[{...details,operation:'model_update',flow_id:'model-update-01'}]},client('pmbu-agent-client'));
await call('/oauth/token',{...request,authorization_details:[{...details,operation:'model_update',qos_tier:'critical'}]},client('pmbu-agent-client'),403);
await call(`/v1/admin/agents/${enrolled.agent.id}/status`,{status:'revoked'},admin);
const revoked=await call('/oauth/introspect',{token:token.access_token},client('pmbu-pcf-adapter'));
if(revoked.active)throw new Error('Revoked token still active');
const result={recordedAt:new Date().toISOString(),identityMode:'local-demo-issuer',checks:{pendingPushBlocked:true,approvedPushIssued:true,signatureVerifiedByIssuer:true,
 backgroundTier:background.authorization_details[0].qos_tier,escalationBlocked:true,revocationInvalidated:true},grantedDetails:claims.authorization_details};
mkdirSync('artifacts',{recursive:true});writeFileSync('artifacts/foundation-results.json',JSON.stringify(result,null,2));console.log('Checks:',result.checks);
