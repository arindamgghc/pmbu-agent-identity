import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createPublicKey,verify} from 'node:crypto';
import {EXCHANGE,JWT_TYPE,RAR_TYPE} from '../rar.js';

// Refresh this private state export before each run; no bearer tokens are printed.
const state=JSON.parse(readFileSync(process.env.PMBU_STATE_FILE||'foundation-data/compose-state.json','utf8'));
const base=process.env.PMBU_URL||'http://127.0.0.1:4191';
const spiffeId='spiffe://pmbu.demo/workloads/security';
const admin='Bearer '+state.adminKey;
const client=name=>'Basic '+Buffer.from(name+':'+state.gatewayKey).toString('base64');
async function call(route,body,auth,expected=200){
 const r=await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json',Authorization:auth},body:JSON.stringify(body)});
 const data=await r.json();
 if(r.status!==expected)throw new Error(route+': '+JSON.stringify(data));
 return data;
}
function fetchSvid(audience){
 let output;
 try{output=execFileSync(process.env.DOCKER||'docker',['compose','exec','-T','spire-client','/opt/spire/bin/spire-agent','api','fetch','jwt','-audience',audience,'-spiffeID',spiffeId],{encoding:'utf8',timeout:15000,stdio:['ignore','pipe','pipe']});}
 catch{throw new Error('SPIRE Workload API fetch failed; check server and agent readiness.');}
 const token=output.match(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)?.[0];
 if(!token)throw new Error('SPIRE did not return a JWT-SVID');
 return token;
}
let agentId=state.foundation?.spiffeMappings?.[spiffeId];
if(!agentId){
 const registration=await call('/v1/admin/agents',{name:'SPIRE home security',deviceId:'spire-container-workload',profile:'security',owner:'demo-human'},admin,201);
 agentId=registration.agent.id;
 await call('/foundation/admin/spiffe-mapping',{agentId,spiffeId},admin);
}
const identity=await call('/foundation/spiffe/exchange',{jwt_svid:fetchSvid('pmbu-rar-issuer')});
if(identity.sourceSpiffeId!==spiffeId||identity.identitySource!=='verified-jwt-svid')throw new Error('Unexpected identity source');
await call('/foundation/spiffe/exchange',{jwt_svid:fetchSvid('wrong-audience')},undefined,401);
const push=await call('/duo/push',{},'Bearer '+identity.token,201);
const details={type:RAR_TYPE,operation:'security_alert',network_context:'access',flow_id:'spire-alert-01',subscriber_id:'DEMO-SUBSCRIBER',pdu_session_id:'demo-session-1',
 flow:{src_ip:'192.0.2.10',dst_ip:'192.0.2.20',src_port:45000,dst_port:443,protocol:'tcp'}};
const request={grant_type:EXCHANGE,subject_token:identity.token,subject_token_type:JWT_TYPE,audience:'pmbu-pcf-adapter',duo_approval_id:push.id,authorization_details:[details]};
await call('/oauth/token',request,client('pmbu-agent-client'),403);
await call('/duo/admin/decide',{push_id:push.id,status:'approved'},admin);
const token=await call('/oauth/token',request,client('pmbu-agent-client'));
const [header,payload,signature]=token.access_token.split('.');
const claims=JSON.parse(Buffer.from(payload,'base64url'));
const jwks=await (await fetch(base+'/.well-known/jwks.json')).json();
if(!verify(null,Buffer.from(header+'.'+payload),createPublicKey({key:jwks.keys[0],format:'jwk'}),Buffer.from(signature,'base64url')))throw new Error('RAR signature invalid');
if(claims.sub!==spiffeId)throw new Error('Verified SPIFFE subject not retained in RAR token');
const active=await call('/oauth/introspect',{token:token.access_token},client('pmbu-pcf-adapter'));
if(!active.active)throw new Error('New RAR token inactive');
await call('/v1/identities/end',{},'Bearer '+identity.token);
const ended=await call('/oauth/introspect',{token:token.access_token},client('pmbu-pcf-adapter'));
if(ended.active)throw new Error('Ended identity still authorizes RAR token');
const result={recordedAt:new Date().toISOString(),identityMode:'live-spire-jwt-svid',spiffeId,
 checks:{workloadSvidVerified:true,wrongAudienceRejected:true,pendingApprovalBlocked:true,rarSignatureVerified:true,spiffeSubjectRetained:true,introspectionActive:true,identityTerminationInvalidated:true},
 grantedDetails:claims.authorization_details,enforcement:claims.enforcement};
mkdirSync('artifacts',{recursive:true});
writeFileSync('artifacts/spire-results.json',JSON.stringify(result,null,2));
console.log(JSON.stringify(result,null,2));
