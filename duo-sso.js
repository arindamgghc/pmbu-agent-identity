import {randomBytes, createHash} from 'node:crypto';
import * as oidc from 'openid-client';
import {requireThat, ServiceError} from './identity.js';

const digest = value => createHash('sha256').update(value).digest('hex');
const cookieName = '__Host-pmbu-duo';
const cookie = (value, seconds) => `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${seconds}`;
const email = value => typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? value.toLowerCase() : undefined;

export function createDuoOidcProvider({issuer, clientId, clientSecret, redirectUri, customFetch} = {}) {
  requireThat(typeof issuer==='string' && issuer && typeof redirectUri==='string' && redirectUri,400,'Duo issuer and redirect URI required');
  const server = new URL(issuer), callback = new URL(redirectUri);
  requireThat(server.protocol === 'https:' && !server.username && !server.password && !server.search && !server.hash,400,'Duo issuer must be an HTTPS issuer URL');
  requireThat(callback.protocol === 'https:' && callback.pathname === '/duo/sso/callback' && !callback.search && !callback.hash && !callback.username && !callback.password,400,'Duo callback must be HTTPS with path /duo/sso/callback');
  requireThat(typeof clientId === 'string' && clientId && typeof clientSecret === 'string' && clientSecret,400,'Duo client credentials required');
  let configuration;
  async function config() {
    configuration ||= oidc.discovery(server,clientId,{id_token_signed_response_alg:'RS256'},oidc.ClientSecretBasic(clientSecret),{
      execute:[oidc.enableNonRepudiationChecks], timeout:10,
      ...(customFetch ? {[oidc.customFetch]:customFetch} : {})
    }).catch(() => { configuration = undefined; throw new ServiceError(502,'Duo discovery unavailable or invalid'); });
    return configuration;
  }
  return {
    issuer:server.href, redirectUri:callback.href,
    async authorization({state,nonce,verifier}) {
      const configuration = await config();
      return oidc.buildAuthorizationUrl(configuration,{
        redirect_uri:callback.href,scope:'openid email',response_mode:'query',state,nonce,
        code_challenge:await oidc.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256',
        prompt:'login',max_age:'120'
      }).href;
    },
    async claims(currentUrl, {state,nonce,verifier}) {
      try {
        const tokens = await oidc.authorizationCodeGrant(await config(),currentUrl,{
          expectedState:state,expectedNonce:nonce,pkceCodeVerifier:verifier,idTokenExpected:true,maxAge:120
        });
        const claims = tokens.claims();
        requireThat(claims,401,'Duo ID token required');
        return claims;
      } catch(error) {
        if(error instanceof ServiceError)throw error;
        throw new ServiceError(401,'Duo login denied or ID token validation failed');
      }
    }
  };
}

export class DuoSso {
  constructor(foundation, provider) {
    requireThat(foundation.duoMode === 'oidc',400,'OIDC mode required');
    this.foundation=foundation;this.provider=provider;
    this.requests=new Map();this.flows=new Map();
  }
  get service(){return this.foundation.service;}
  pending(id) {
    const push=this.foundation.state.pushes[id];
    const agent=this.service.state.agents[push?.agentId],session=this.service.state.sessions[push?.sessionId];
    requireThat(push && push.source==='oidc' && push.status==='pending' && push.expiresAt>this.service.clock() &&
      agent?.status==='active' && agent.owner===push.owner && agent.profile===push.group &&
      session && !session.revoked && session.agentId===agent.id && session.expiresAt>this.service.clock(),401,'Duo request or agent session is inactive');
    return push;
  }
  prune() {
    for(const map of [this.requests,this.flows])for(const [key,value] of map)
      if(value.expiresAt<=this.service.clock())map.delete(key);
  }
  request(identityToken, body={}) {
    this.prune();requireThat(this.requests.size+this.flows.size<1000,429,'Too many pending Duo logins');
    const {agent}=this.service.validate(identityToken,'identity');
    requireThat(email(agent.owner),400,'Register the agent owner as the Duo user email before starting SSO');
    const push=this.foundation.push(identityToken,body);
    const ticket=randomBytes(32).toString('base64url');
    this.requests.set(digest(ticket),{pushId:push.id,expiresAt:push.expiresAt});
    const url=new URL('/duo/sso/start',this.provider.redirectUri);url.searchParams.set('request',ticket);
    return {...push,loginUrl:url.href};
  }
  async start(ticket) {
    requireThat(typeof ticket==='string'&&/^[A-Za-z0-9_-]{43}$/.test(ticket),400,'Invalid Duo login link');
    const key=digest(ticket),request=this.requests.get(key);
    requireThat(request && request.expiresAt>this.service.clock(),401,'Duo login link missing, expired or already used');
    this.requests.delete(key);
    const push=this.pending(request.pushId);
    const state=oidc.randomState(),nonce=oidc.randomNonce(),verifier=oidc.randomPKCECodeVerifier();
    const browser=randomBytes(32).toString('base64url');
    const location=await this.provider.authorization({state,nonce,verifier});
    this.pending(push.id);
    this.flows.set(state,{pushId:push.id,nonce,verifier,browserHash:digest(browser),expiresAt:push.expiresAt});
    return {location,cookie:cookie(browser,push.expiresAt-this.service.clock())};
  }
  async callback(currentUrl, cookieHeader='') {
    requireThat(currentUrl.searchParams.getAll('state').length===1,400,'Invalid Duo state');
    const state=currentUrl.searchParams.get('state'),flow=this.flows.get(state);
    requireThat(flow && flow.expiresAt>this.service.clock(),401,'Duo login state missing, expired or already used');
    this.flows.delete(state); // Consume before awaiting anything: callback cannot be replayed.
    const values=cookieHeader.split(';').map(s=>s.trim()).filter(s=>s.startsWith(cookieName+'='));
    const browser=values.length===1 ? values[0].slice(cookieName.length+1) : '';
    requireThat(browser && digest(browser)===flow.browserHash,401,'Duo browser session mismatch');
    const push=this.pending(flow.pushId);
    try {
      const claims=await this.provider.claims(currentUrl,{state,nonce:flow.nonce,verifier:flow.verifier});
      this.pending(push.id);
      requireThat(claims.iss===this.provider.issuer && typeof claims.sub==='string' && claims.sub,401,'Invalid Duo subject or issuer');
      requireThat(email(claims.email) && email(claims.email)===email(push.owner),403,'Duo login does not match the registered agent owner');
      requireThat(Array.isArray(claims.amr)&&claims.amr.includes('mfa'),403,'Duo MFA evidence required; bypass logins cannot approve an agent');
      push.status='approved';push.ownerSubject=claims.sub;push.ownerIssuer=claims.iss;push.mfaVerified=true;
      this.service.event('duo.oidc.approved',{agentId:push.agentId,sessionId:push.sessionId,pushId:push.id,ownerSubject:claims.sub});
      return {id:push.id,sessionId:push.sessionId,status:push.status,expiresAt:push.expiresAt,source:'oidc',mfaVerified:true};
    } catch(error) {
      push.status='denied';this.service.event('duo.oidc.denied',{agentId:push.agentId,sessionId:push.sessionId,pushId:push.id});
      throw error;
    }
  }
  async handle(req,res,url) {
    const send=(status,data,headers={})=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store',...headers});res.end(JSON.stringify(data));};
    try {
      if(req.method==='GET' && url.pathname==='/duo/sso/start') {
        requireThat(url.searchParams.getAll('request').length===1,400,'Invalid Duo login link');
        const result=await this.start(url.searchParams.get('request'));
        res.writeHead(302,{'Location':result.location,'Set-Cookie':result.cookie,'Cache-Control':'no-store'});res.end();
      } else if(req.method==='GET' && url.pathname==='/duo/sso/callback') {
        const currentUrl=new URL(this.provider.redirectUri);currentUrl.search=url.search;
        send(200,await this.callback(currentUrl,req.headers.cookie),{'Set-Cookie':cookie('',0)});
      } else if(req.method==='POST' && url.pathname==='/duo/sso/requests') {
        requireThat(req.headers['content-type']?.split(';')[0]==='application/json',415,'Use application/json');
        let text='';for await(const chunk of req){text+=chunk;requireThat(Buffer.byteLength(text)<=65536,413,'Request too large');}
        let body;try{body=JSON.parse(text);}catch{throw new ServiceError(400,'Invalid JSON');}
        requireThat(body&&typeof body==='object'&&!Array.isArray(body),400,'Object required');
        const token=/^Bearer ([^\s]+)$/.exec(req.headers.authorization||'')?.[1];
        send(201,this.request(token,body));
      } else if(req.method==='GET' && /^\/duo\/sso\/requests\/[a-zA-Z0-9-]+$/.test(url.pathname)) {
        const token=/^Bearer ([^\s]+)$/.exec(req.headers.authorization||'')?.[1];
        const {agent,session}=this.service.validate(token,'identity');
        const push=this.foundation.state.pushes[url.pathname.split('/').at(-1)];
        requireThat(push && push.source==='oidc' && push.agentId===agent.id && push.sessionId===session.id,404,'Duo request not found for this session');
        send(200,{id:push.id,status:push.expiresAt>this.service.clock()?push.status:'expired',expiresAt:push.expiresAt,source:'oidc',mfaVerified:push.mfaVerified===true});
      } else throw new ServiceError(404,'Unknown Duo SSO endpoint');
    } catch(error) {
      send(error.status||500,{error:'request_failed',error_description:error.status?error.message:'Duo SSO unavailable'},
        url.pathname==='/duo/sso/callback'?{'Set-Cookie':cookie('',0)}:{});
    }
    return true;
  }
}
