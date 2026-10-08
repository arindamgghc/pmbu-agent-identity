import http from 'node:http';
import {readFileSync} from 'node:fs';
import {fileURLToPath, pathToFileURL} from 'node:url';
import path from 'node:path';
import {IdentityService, requireThat, ServiceError} from './identity.js';
import {dispatch, runDemo} from './gateway.js';
import {EXCHANGE, JWT_TYPE, RAR_TYPE} from './rar.js';

const root = path.dirname(fileURLToPath(import.meta.url));
export function createServer(service, {foundation,publicOrigin} = {}) {
  return http.createServer(async (req,res)=>{
    res.setHeader('Cache-Control','no-store');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    const send = (status, data) => {res.writeHead(status, {'Content-Type':'application/json'}); res.end(JSON.stringify(data));};
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      const route = url.pathname;
      if (foundation && await foundation.handle(req,res,url)) return;
      if (req.method === 'GET' && route === '/health') return send(200,{status:'ok',service:'pmbu-agent-identity'});
      const assets = {'/':['index.html','text/html'], '/app.js':['app.js','text/javascript'], '/style.css':['style.css','text/css']};
      if (req.method === 'GET' && Object.hasOwn(assets,route)) {
        const [file,type] = assets[route];
        res.writeHead(200,{'Content-Type':type}); return res.end(readFileSync(path.join(root,'public',file)));
      }
      // No CORS: the dashboard and service share an origin. API clients do not need Origin.
      if (req.headers.origin) requireThat(req.headers.origin === (publicOrigin||`http://${req.headers.host}`),403,'Cross-origin request denied');
      const bearer = /^Bearer ([^\s]+)$/.exec(req.headers.authorization || '')?.[1];
      const admin = route.startsWith('/v1/admin/') || route === '/v1/demo';
      const gateway = route.startsWith('/v1/gateway/');
      if (admin) service.authenticate(bearer,'admin');
      if (gateway) service.authenticate(bearer,'gateway');
      const body = ['POST','PUT','PATCH'].includes(req.method) ? await readBody(req) : {};
      if (req.method === 'GET' && route === '/v1/admin/snapshot') return send(200,{...service.snapshot(),networkControls:{available:!!foundation,pcfEnabled:!!foundation?.pcfClient,duoMode:foundation ? (foundation.duoMode||'simulator') : undefined}});
      if (req.method === 'POST' && route === '/v1/admin/agents') return send(201,service.register(body));
      const activityRoute = /^\/v1\/admin\/agents\/([a-zA-Z0-9-]+)\/activity$/.exec(route);
      if (req.method === 'POST' && activityRoute) {
        requireThat(foundation,503,'Network activity controls require the foundation service on port 4191');
        const {agent,session}=service.validate(body.identityToken,'identity');
        requireThat(agent.id===activityRoute[1],403,'Identity token belongs to a different agent');
        requireThat(['health','security'].includes(agent.profile),403,'Alert controls require a health or security agent');
        requireThat(['alert','background'].includes(body.action),400,'Choose alert or background');
        requireThat(session.agentIp && session.agentPort,400,'Authenticate with the actual UE IP and agent source port first');
        const operation=body.action==='background'?'model_update':agent.profile==='health'?'health_alert':'security_alert';
        const detail={type:RAR_TYPE,operation,network_context:body.context,flow_id:body.flowId,
          subscriber_id:body.subscriberId,pdu_session_id:body.pduSessionId,
          flow:{src_ip:session.agentIp,src_port:session.agentPort,dst_ip:body.destinationIp,dst_port:body.destinationPort,protocol:body.protocol}};
        return send(200,await foundation.issueWithPcf({grant_type:EXCHANGE,subject_token_type:JWT_TYPE,
          subject_token:body.identityToken,audience:'pmbu-pcf-adapter',duo_approval_id:body.approvalId,authorization_details:[detail]}));
      }
      const ownerRoute = /^\/v1\/admin\/agents\/([a-zA-Z0-9-]+)\/owner$/.exec(route);
      if (req.method === 'POST' && ownerRoute) return send(200,service.setOwner(ownerRoute[1],body.owner));
      const agentRoute = /^\/v1\/admin\/agents\/([a-zA-Z0-9-]+)\/status$/.exec(route);
      if (req.method === 'POST' && agentRoute) return send(200,service.setStatus(agentRoute[1],body.status));
      if (req.method === 'PUT' && route === '/v1/admin/policy') return send(200,service.replaceRules(body.rules));
      if (req.method === 'POST' && route === '/v1/identities') return send(201,service.issueIdentity(bearer,body));
      if (req.method === 'POST' && route === '/v1/identities/renew') return send(200,service.renew(bearer,body));
      if (req.method === 'POST' && route === '/v1/identities/end') return send(200,service.endIdentity(bearer));
      if (req.method === 'POST' && route === '/v1/activities') return send(201,service.issueActivity(bearer,body));
      if (req.method === 'POST' && route === '/v1/activities/end') return send(200,service.endActivity(bearer));
      if (req.method === 'POST' && route === '/v1/gateway/evaluate') return send(200,service.evaluate(body.token,body));
      if (req.method === 'POST' && route === '/v1/gateway/dispatch') return send(200,dispatch(service,body.jobs));
      if (req.method === 'POST' && route === '/v1/gateway/feedback') return send(202,service.feedback(body));
      if (req.method === 'POST' && route === '/v1/demo') return send(200,runDemo(service,body.context));
      throw new ServiceError(404,'Unknown endpoint');
    } catch (error) {
      const status = error.status || 500;
      send(status,{error:status === 500 ? 'Internal service error' : error.message});
    }
  });
}
async function readBody(req) {
  requireThat(req.headers['content-type']?.split(';')[0] === 'application/json',415,'Use application/json');
  let text = '';
  for await (const chunk of req) {
    text += chunk.toString();
    requireThat(Buffer.byteLength(text) <= 65536,413,'Request too large');
  }
  try {
    const value = JSON.parse(text);
    requireThat(value && typeof value === 'object' && !Array.isArray(value),400,'JSON object required');
    return value;
  } catch (error) { if (error instanceof ServiceError) throw error; throw new ServiceError(400,'Invalid JSON'); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const directory = process.env.PMBU_DATA_DIR || path.join(root,'data');
  const service = new IdentityService({directory});
  const port = Number(process.env.PORT || 4180);
  // Loopback only. External deployment must add TLS, workload attestation and a secret manager.
  const server = createServer(service);
  server.listen(port,'127.0.0.1',()=>{
    console.log(`PMBU dashboard: http://127.0.0.1:${port}`);
    console.log(`Local credentials: ${path.join(directory,'state.json')} (mode 0600)`);
    console.log('Paste adminKey from that file into the dashboard. npm run demo reads it locally.');
  });
}
