import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {IdentityService} from './identity.js';
import {createServer} from './server.js';
import {Foundation} from './rar.js';
import {PcfClient} from './pcf.js';
import {DuoSso,createDuoOidcProvider} from './duo-sso.js';
import {readFileSync} from 'node:fs';
const root=path.dirname(fileURLToPath(import.meta.url));
const service=new IdentityService({directory:process.env.PMBU_DATA_DIR||path.join(root,'foundation-data')});
const pcfClient=process.env.PMBU_PCF_ENDPOINT ? new PcfClient({endpoint:process.env.PMBU_PCF_ENDPOINT,
  policies:JSON.parse(process.env.PMBU_PCF_POLICIES||'{}')}) : undefined;
const duoMode=process.env.PMBU_DUO_MODE||'simulator';
const foundation=new Foundation(service,{issuer:process.env.PMBU_ISSUER||'http://127.0.0.1:4191',bundlePath:process.env.SPIRE_BUNDLE_PATH,pcfClient,duoMode});
if(duoMode==='oidc'){
  const clientSecret=process.env.DUO_CLIENT_SECRET_FILE ? readFileSync(process.env.DUO_CLIENT_SECRET_FILE,'utf8').trim() : process.env.DUO_CLIENT_SECRET;
  foundation.sso=new DuoSso(foundation,createDuoOidcProvider({issuer:process.env.DUO_ISSUER,clientId:process.env.DUO_CLIENT_ID,
    clientSecret,redirectUri:process.env.DUO_REDIRECT_URI}));
}
const server=createServer(service,{foundation,publicOrigin:foundation.sso?new URL(process.env.DUO_REDIRECT_URI).origin:undefined});
server.on('error',error=>{console.error(error.code==='EADDRINUSE'?'Foundation port already in use. Use the existing server or change PORT.':error.message);process.exit(1);});
server.listen(Number(process.env.PORT||4191),process.env.PMBU_HOST||'127.0.0.1',()=>console.log('Identity + Duo ('+duoMode+') + RAR issuer ready on port '+(process.env.PORT||4191)));
