import {connect} from 'node:http2';
import {isIP} from 'node:net';
import {requireThat, ServiceError} from './identity.js';

// This lab endpoint uses HTTP/2 prior knowledge (h2c), matching Abdullah's curl.
export class PcfClient {
  constructor({endpoint, policies = {}, timeoutMs = 5000} = {}) {
    this.endpoint = new URL(endpoint);
    requireThat(['http:', 'https:'].includes(this.endpoint.protocol) && !this.endpoint.username && !this.endpoint.password, 400, 'Invalid PCF endpoint');
    requireThat(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 30000, 400, 'Invalid PCF timeout');
    requireThat(policies && typeof policies === 'object' && !Array.isArray(policies) && Object.entries(policies).every(([tier, policy]) =>
      ['background', 'interactive', 'critical'].includes(tier) && typeof policy === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(policy)), 400, 'Invalid PCF policy mapping');
    this.policies = policies;
    this.timeoutMs = timeoutMs;
  }
  async apply({agentIp, agentPort, qosTier}) {
    requireThat(typeof agentIp === 'string' && isIP(agentIp) && Number.isInteger(agentPort) && agentPort >= 1 && agentPort <= 65535, 400, 'PCF requires authenticated agentIp and agentPort');
    const policy = this.policies[qosTier];
    requireThat(policy, 503, 'PCF policy mapping missing for ' + qosTier);
    const payload = {agentIP:agentIp, agentPort:String(agentPort), policy};
    return new Promise((resolve, reject) => {
      const connection = connect(this.endpoint.origin);
      let stream, done = false, status;
      const finish = (error, result) => {
        if (done) return;
        done = true; clearTimeout(timer); stream?.close(); connection.destroy();
        if (error) reject(error); else resolve(result);
      };
      const timer = setTimeout(() => finish(new ServiceError(504, 'PCF request timed out; application status unknown')), this.timeoutMs);
      connection.on('error', () => finish(new ServiceError(502, 'PCF connection failed; application status unknown')));
      connection.on('connect', () => {
        if (done) return;
        stream = connection.request({':method':'POST', ':path':this.endpoint.pathname + this.endpoint.search, 'content-type':'application/json'});
        let bytes = 0;
        stream.on('response', headers => { status = Number(headers[':status']); });
        stream.on('data', chunk => { bytes += chunk.length; if (bytes > 65536) finish(new ServiceError(502, 'PCF response too large; application status unknown')); });
        stream.on('error', () => finish(new ServiceError(502, 'PCF request failed; application status unknown')));
        stream.on('end', () => {
          if (status >= 200 && status < 300) finish(null, {status:'api_accepted', httpStatus:status, ...payload, networkEnforcementVerified:false});
          else finish(new ServiceError(502, 'PCF API did not accept the policy request'));
        });
        stream.end(JSON.stringify(payload));
      });
    });
  }
}
