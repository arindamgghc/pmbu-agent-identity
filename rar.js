import {randomUUID, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {isIP} from 'node:net';
import {requireThat, ServiceError, CONTEXTS, CLASSES} from './identity.js';
export const RAR_TYPE='urn:pmbu:authorization:network-qos';
export const EXCHANGE='urn:ietf:params:oauth:grant-type:token-exchange';
export const JWT_TYPE='urn:ietf:params:oauth:token-type:jwt';
export const ACCESS_TYPE='urn:ietf:params:oauth:token-type:access_token';
// Illustrative demo mapping only; Abdullah must supply an approved operator mapping.
export const QOS={background:{'5qi':9,dscp:8},interactive:{'5qi':8,dscp:0},critical:{'5qi':7,dscp:46}};
export class Foundation {
 constructor(service,{issuer='http://127.0.0.1:4191',bundlePath,pcfClient}={}) {
  this.service=service;this.issuer=issuer;this.bundlePath=bundlePath;this.pcfClient=pcfClient;
  service.state.foundation ||= {pushes:{},tokens:{},spiffeMappings:{}};
 }
 get state(){return this.service.state.foundation;}
 jwks(){return {keys:[{...createPublicKey(this.service.state.publicKey).export({format:'jwk'}),kid:'pmbu-demo-1',alg:'EdDSA',use:'sig'}]};}
 metadata(){return {issuer:this.issuer,token_endpoint:this.issuer+'/oauth/token',jwks_uri:this.issuer+'/.well-known/jwks.json',
  introspection_endpoint:this.issuer+'/oauth/introspect',grant_types_supported:[EXCHANGE],token_endpoint_auth_methods_supported:['client_secret_basic'],
  authorization_details_types_supported:[RAR_TYPE],demo_only:true};}
 push(identityToken,{agentIp,agentPort}={}){
  const {agent,session}=this.service.validate(identityToken,'identity');
  if(agentPort!==undefined){requireThat(Number.isInteger(agentPort)&&agentPort>=1&&agentPort<=65535,400,'Invalid agentPort');requireThat(agentPort===session.agentPort,403,'Duo agentPort must match authenticated session');}
  if(agentIp!==undefined){this.service.agentAddress(agentIp);requireThat(agentIp===session.agentIp,403,'Duo agentIp must match authenticated session');}
  const address=this.service.agentAddress(session.agentIp,session.agentPort);
  const push={id:randomUUID(),agentId:agent.id,sessionId:session.id,owner:agent.owner,group:agent.profile,...address,status:'pending',expiresAt:this.service.clock()+120};
  this.state.pushes[push.id]=push;this.service.event('duo.push.pending',{agentId:agent.id,pushId:push.id,owner:agent.owner});return push;
 }
 decide(id,status){
  const p=this.state.pushes[id];requireThat(p && p.expiresAt>this.service.clock(),404,'Push missing or expired');
  requireThat(p.status==='pending',409,'Push already decided');requireThat(['approved','denied'].includes(status),400,'Invalid push decision');
  p.status=status;this.service.event('duo.push.'+status,{agentId:p.agentId,pushId:id});return p;
 }
 bind({agentId,spiffeId}){
  requireThat(this.service.state.agents[agentId],404,'Unknown agent');
  requireThat(typeof spiffeId==='string' && /^spiffe:\/\/pmbu.demo\/[a-zA-Z0-9/_-]+$/.test(spiffeId),400,'Invalid SPIFFE ID');
  requireThat(!this.state.spiffeMappings[spiffeId] || this.state.spiffeMappings[spiffeId]===agentId,409,'SPIFFE ID already mapped');
  this.state.spiffeMappings[spiffeId]=agentId;this.service.event('spiffe.mapped',{agentId,spiffeId});return {agentId,spiffeId};
 }
 exchangeSvid(token,{agentIp,agentPort}={}){
  requireThat(this.bundlePath,503,'SPIRE trust bundle not configured');
  try {
   const parts=token.split('.');requireThat(parts.length===3,401,'Malformed SVID');
   const header=JSON.parse(Buffer.from(parts[0],'base64url'));const claims=JSON.parse(Buffer.from(parts[1],'base64url'));
   requireThat(['RS256','ES256'].includes(header.alg),401,'Unsupported SVID algorithm');
   const bundle=JSON.parse(readFileSync(this.bundlePath,'utf8'));
   const key=bundle.keys?.find(k=>k.kid===header.kid && k.use==='jwt-svid' && (header.alg==='RS256'?k.kty==='RSA':k.kty==='EC'&&k.crv==='P-256'));
   requireThat(key,401,'Untrusted SVID key');
   const publicKey=createPublicKey({key,format:'jwk'});
   requireThat(verify('sha256',Buffer.from(parts.slice(0,2).join('.')),{key:publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')),401,'Invalid SVID signature');
   requireThat(Number.isInteger(claims.exp)&&claims.exp>this.service.clock() && Number.isInteger(claims.iat)&&claims.iat<=this.service.clock() &&
    (Array.isArray(claims.aud)?claims.aud.includes('pmbu-rar-issuer'):claims.aud==='pmbu-rar-issuer'),401,'Expired SVID or wrong audience');
   const agentId=this.state.spiffeMappings[claims.sub];const agent=this.service.state.agents[agentId];
   requireThat(agent&&agent.status==='active',403,'SPIFFE subject not mapped to active agent');
   const session={id:randomUUID(),agentId,...this.service.agentAddress(agentIp,agentPort),expiresAt:Math.min(claims.exp,this.service.clock()+600),revoked:false,source:'spire',sourceSpiffeId:claims.sub,sourceExpiresAt:claims.exp};
   this.service.state.sessions[session.id]=session;this.service.event('spiffe.exchanged',{agentId,spiffeId:claims.sub,sessionId:session.id});
   return {...this.service.identityResponse(session),sourceSpiffeId:claims.sub,identitySource:'verified-jwt-svid'};
  } catch(error){if(error instanceof ServiceError)throw error;throw new ServiceError(401,'SVID or trust bundle invalid');}
 }
 issue(body){
  requireThat(body.grant_type===EXCHANGE,400,'unsupported_grant_type');
  requireThat(body.subject_token_type===JWT_TYPE && (!body.requested_token_type||body.requested_token_type===ACCESS_TYPE),400,'invalid_request');
  requireThat(body.audience==='pmbu-pcf-adapter',400,'invalid_target');
  requireThat(body.actor_token===undefined && body.actor_token_type===undefined,400,'Actor delegation is not supported');
  const {agent,session,claims}=this.service.validate(body.subject_token,'identity');
  const push=this.state.pushes[body.duo_approval_id];
  requireThat(push && push.status==='approved' && push.expiresAt>this.service.clock() && push.agentId===agent.id && push.sessionId===session.id && push.group===agent.profile,403,'Duo emulator approval required for this identity');
  let details;try{details=typeof body.authorization_details==='string'?JSON.parse(body.authorization_details):body.authorization_details;}catch{throw new ServiceError(400,'invalid_authorization_details');}
  requireThat(Array.isArray(details)&&details.length===1 && details[0]&&details[0].type===RAR_TYPE,400,'invalid_authorization_details');
  const d=details[0];
  const allowed=['type','operation','network_context','flow_id','flow','subscriber_id','pdu_session_id','qos_tier','5qi','dscp'];
  requireThat(Object.keys(d).every(k=>allowed.includes(k)),400,'invalid_authorization_details');
  const tier=this.service.state.policy.rules[agent.profile]?.[d.operation];
  requireThat(tier && Object.hasOwn(CLASSES,tier),403,'Operation not authorized');
  requireThat(CONTEXTS.includes(d.network_context) && typeof d.flow_id==='string' && /^[a-zA-Z0-9._:-]{1,100}$/.test(d.flow_id),400,'Invalid flow/context');
  const f=d.flow;
  requireThat(f && Object.keys(f).every(k=>['src_ip','dst_ip','src_port','dst_port','protocol'].includes(k)),400,'invalid_authorization_details');
  requireThat(f&&isIP(f.src_ip)&&isIP(f.dst_ip)&&['tcp','udp'].includes(f.protocol)&&[f.src_port,f.dst_port].every(p=>Number.isInteger(p)&&p>0&&p<=65535),400,'Valid observed-flow tuple required');
  requireThat(session.agentIp===undefined||f.src_ip===session.agentIp,403,'Flow source IP must match authenticated agentIp');
  requireThat(session.agentPort===undefined||f.src_port===session.agentPort,403,'Flow source port must match authenticated agentPort');
  for(const key of ['subscriber_id','pdu_session_id'])requireThat(typeof d[key]==='string'&&d[key].length>0&&d[key].length<=100,400,'Missing '+key);
  requireThat(!d.qos_tier||d.qos_tier===tier,403,'Requested QoS exceeds or differs from enterprise policy');
  const qos=QOS[tier];for(const key of ['5qi','dscp'])requireThat(d[key]===undefined||d[key]===qos[key],403,'Requested QoS mapping not allowed');
  const granted={type:RAR_TYPE,operation:d.operation,network_context:d.network_context,flow_id:d.flow_id,
    flow:{src_ip:f.src_ip,dst_ip:f.dst_ip,src_port:f.src_port,dst_port:f.dst_port,protocol:f.protocol},subscriber_id:d.subscriber_id,pdu_session_id:d.pdu_session_id,
    qos_tier:tier,...qos,qos_mapping_status:'demo_only',flow_binding_verified:false};
  const exp=Math.min(claims.exp,session.expiresAt,this.service.clock()+120);const id=randomUUID();
  const address=this.service.agentAddress(session.agentIp,session.agentPort);
  const payload={iss:this.issuer,kind:'rar',aud:'pmbu-pcf-adapter',sub:session.sourceSpiffeId||claims.sub,agentId:agent.id,sessionId:session.id,...address,
    client_id:'pmbu-agent-client',jti:id,exp,enterprise_group:agent.profile,policy_version:this.service.state.policy.version,
    authorization_details:[granted],qos_tier:tier,...qos,qos_mapping_status:'demo_only',enforcement:this.pcfClient?'pcf_requested':'dry_run_only'};
  this.state.tokens[id]=payload;this.service.event('rar.issued',{agentId:agent.id,jti:id,operation:d.operation,qosTier:tier});
  return {access_token:this.service.sign(payload),issued_token_type:ACCESS_TYPE,token_type:'Bearer',expires_in:exp-this.service.clock(),authorization_details:[granted]};
 }
 async issueWithPcf(body){
  // issue() checks active workload identity, session-bound Duo approval and activity policy first.
  const result=this.issue(body);
  if(!this.pcfClient)return result;
  const claims=JSON.parse(Buffer.from(result.access_token.split('.')[1],'base64url'));
  try{
   const pcf=await this.pcfClient.apply({agentIp:claims.agentIp,agentPort:claims.agentPort,qosTier:claims.qos_tier});
   // Identity could expire or be revoked while waiting on the network.
   requireThat(this.introspect(result.access_token).active,401,'Identity or authorization became inactive during PCF request');
   this.service.event('pcf.api_accepted',{agentId:claims.agentId,sessionId:claims.sessionId,jti:claims.jti,policy:pcf.policy,httpStatus:pcf.httpStatus});
   return {...result,pcf};
  }catch(error){
   delete this.state.tokens[claims.jti];
   this.service.event('pcf.request_failed',{agentId:claims.agentId,sessionId:claims.sessionId,jti:claims.jti});
   throw error;
  }
 }
 introspect(token){
  try{
   const [h,p,s,...extra]=token.split('.');requireThat(h&&p&&s&&extra.length===0,401,'Invalid token');
   const head=JSON.parse(Buffer.from(h,'base64url'));
   requireThat(head.alg==='EdDSA'&&head.kid==='pmbu-demo-1'&&verify(null,Buffer.from(h+'.'+p),this.service.state.publicKey,Buffer.from(s,'base64url')),401,'Invalid signature');
   const c=JSON.parse(Buffer.from(p,'base64url'));const stored=this.state.tokens[c.jti];const a=this.service.state.agents[c.agentId],session=this.service.state.sessions[c.sessionId];
   requireThat(stored&&c.kind==='rar'&&c.iss===this.issuer&&c.aud==='pmbu-pcf-adapter'&&c.exp>this.service.clock()&&a?.status==='active'&&session&&!session.revoked&&session.expiresAt>this.service.clock()&&c.policy_version===this.service.state.policy.version,401,'Inactive entitlement');
   return {active:true,...c};
  }catch{return {active:false};}
 }
 async handle(req,res,url){
  const route=url.pathname;
  if(!route.startsWith('/oauth/')&&!route.startsWith('/duo/')&&!route.startsWith('/foundation/')&&!['/.well-known/jwks.json','/.well-known/oauth-authorization-server'].includes(route))return false;
  const send=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
  try{
   if(req.method==='GET'&&route==='/.well-known/jwks.json'){send(200,this.jwks());return true;}
   if(req.method==='GET'&&route==='/.well-known/oauth-authorization-server'){send(200,this.metadata());return true;}
   const bearer=/^Bearer ([^\s]+)$/.exec(req.headers.authorization||'')?.[1];
   if(['/duo/admin/decide','/foundation/admin/spiffe-mapping'].includes(route))this.service.authenticate(bearer,'admin');
   if(['/oauth/token','/oauth/introspect'].includes(route)){
    const basic=/^Basic (.+)$/.exec(req.headers.authorization||'');requireThat(basic,401,'Client authentication required');
    const decoded=Buffer.from(basic[1],'base64').toString();const colon=decoded.indexOf(':');
    requireThat(decoded.slice(0,colon)===(route==='/oauth/token'?'pmbu-agent-client':'pmbu-pcf-adapter'),401,'Wrong client');
    this.service.authenticate(decoded.slice(colon+1),'gateway');
   }
   requireThat(req.method==='POST',405,'POST required');
   const type=req.headers['content-type']?.split(';')[0];let text='';for await(const chunk of req){text+=chunk;requireThat(Buffer.byteLength(text)<=65536,413,'Request too large');}
   let body;
   if(type==='application/x-www-form-urlencoded'){const params=new URLSearchParams(text);requireThat(new Set(params.keys()).size===[...params.keys()].length,400,'Duplicate parameters');body=Object.fromEntries(params);}
   else {requireThat(type==='application/json',415,'Use JSON or form encoding');try{body=JSON.parse(text);}catch{throw new ServiceError(400,'Invalid JSON');}}
   requireThat(body&&typeof body==='object'&&!Array.isArray(body),400,'Object required');
   if(route==='/duo/push')send(201,this.push(bearer,body));
   else if(route==='/duo/admin/decide')send(200,this.decide(body.push_id,body.status));
   else if(route==='/foundation/admin/spiffe-mapping')send(200,this.bind(body));
   else if(route==='/foundation/spiffe/exchange')send(200,this.exchangeSvid(body.jwt_svid,body));
   else if(route==='/oauth/token')send(200,await this.issueWithPcf(body));
   else if(route==='/oauth/introspect')send(200,this.introspect(body.token));
   else throw new ServiceError(404,'Unknown endpoint');
  }catch(error){send(error.status||500,{error:route==='/oauth/token'?(error.message==='unsupported_grant_type'?error.message:error.message==='invalid_authorization_details'||/QoS|flow\/context|tuple|required$|not authorized/.test(error.message)&&error.status!==401? 'invalid_authorization_details':'invalid_grant'):'request_failed',error_description:error.status?error.message:'Internal service error'});}
  return true;
 }
}
