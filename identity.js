import {generateKeyPairSync, randomBytes, randomUUID, createHash, sign, verify, timingSafeEqual} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync, renameSync} from 'node:fs';
import path from 'node:path';
import {isIP} from 'node:net';

export class ServiceError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export function requireThat(condition, status, message) {
  if (!condition) throw new ServiceError(status, message);
}
const hash = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('base64url');
const json64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
export const CONTEXTS = ['access', 'edge', 'enterprise'];
export const CLASSES = {
  background: {rank: 1, dscp: 8, queue: 'background'},
  interactive: {rank: 2, dscp: 0, queue: 'interactive'},
  critical: {rank: 3, dscp: 46, queue: 'critical'}
};
const rules = {
  recipe: {recipe_fetch: 'background', model_update: 'background'},
  travel: {booking: 'interactive', model_update: 'background'},
  health: {model_update: 'background', health_alert: 'critical'},
  security: {model_update: 'background', security_alert: 'critical'}
};
export class IdentityService {
  constructor({directory, clock = () => Math.floor(Date.now()/1000)} = {}) {
    this.directory = directory;
    this.clock = clock;
    if (directory) mkdirSync(directory, {recursive: true, mode: 0o700});
    const file = directory && path.join(directory, 'state.json');
    if (file && existsSync(file)) this.state = JSON.parse(readFileSync(file, 'utf8'));
    else {
      const pair = generateKeyPairSync('ed25519');
      this.state = {
        privateKey: pair.privateKey.export({type:'pkcs8', format:'pem'}),
        publicKey: pair.publicKey.export({type:'spki', format:'pem'}),
        adminKey: secret(), gatewayKey: secret(), agents: {}, sessions: {}, activities: {},
        policy: {version: 1, rules, maxIdentitySeconds: 600, maxActivitySeconds: 120}, audit: []
      };
      this.save();
    }
  }
  save() {
    if (!this.directory) return;
    const file = path.join(this.directory, 'state.json');
    writeFileSync(file + '.tmp', JSON.stringify(this.state, null, 2), {mode:0o600});
    renameSync(file + '.tmp', file);
  }
  event(type, details) {
    this.state.audit.push({id:randomUUID(), at:this.clock(), type, ...details});
    this.state.audit = this.state.audit.slice(-500);
    this.save();
  }
  authenticate(value, role) {
    const expected = this.state[role + 'Key'];
    requireThat(typeof value === 'string' && expected && Buffer.byteLength(value) === Buffer.byteLength(expected) &&
      timingSafeEqual(Buffer.from(value), Buffer.from(expected)), 401, 'Invalid ' + role + ' credential');
  }
  ttl(value, max) {
    const seconds = value ?? max;
    requireThat(Number.isInteger(seconds) && seconds > 0 && seconds <= max, 400, `ttlSeconds must be 1..${max}`);
    return seconds;
  }
  agentAddress(agentIp, agentPort) {
    if (agentIp !== undefined) requireThat(typeof agentIp === 'string' && isIP(agentIp), 400, 'Invalid agentIp');
    if (agentPort !== undefined) requireThat(agentIp !== undefined && Number.isInteger(agentPort) && agentPort >= 1 && agentPort <= 65535, 400, 'agentPort requires agentIp and must be an integer 1..65535');
    return agentIp === undefined ? {} : {agentIp, ...(agentPort === undefined ? {} : {agentPort}), agentIpVerified:false};
  }
  register({name, deviceId, profile, owner = 'hackfest-team'}) {
    for (const [key, value] of Object.entries({name, deviceId, owner}))
      requireThat(typeof value === 'string' && value.trim().length > 0 && value.length <= 120, 400, `Invalid ${key}`);
    requireThat(Object.hasOwn(this.state.policy.rules, profile), 400, 'Unknown profile');
    const enrollmentToken = secret();
    const agent = {id:randomUUID(), name, deviceId, profile, owner, status:'active', createdAt:this.clock(),
      enrollmentHash:hash(enrollmentToken), enrollmentExpiresAt:this.clock()+300, enrollmentUsed:false};
    this.state.agents[agent.id] = agent;
    this.event('agent.registered', {agentId:agent.id, profile});
    return {agent:this.publicAgent(agent), enrollmentToken, enrollmentExpiresAt:agent.enrollmentExpiresAt};
  }
  publicAgent(agent) {
    const {enrollmentHash, enrollmentUsed, enrollmentExpiresAt, ...safe} = agent;
    return safe;
  }
  setStatus(id, status) {
    const agent = this.state.agents[id];
    requireThat(agent, 404, 'Unknown agent');
    requireThat(['active','suspended','revoked'].includes(status), 400, 'Invalid status');
    requireThat(agent.status !== 'revoked' || status === 'revoked', 409, 'Revocation is terminal; register a new agent');
    agent.status = status;
    if (status !== 'active') for (const session of Object.values(this.state.sessions))
      if (session.agentId === id) session.revoked = true;
    this.event('agent.' + status, {agentId:id});
    return this.publicAgent(agent);
  }
  issueIdentity(enrollmentToken, {agentId, ttlSeconds, agentIp, agentPort}) {
    const agent = this.state.agents[agentId];
    requireThat(agent && agent.status === 'active' && !agent.enrollmentUsed &&
      this.clock() < agent.enrollmentExpiresAt && typeof enrollmentToken === 'string' &&
      hash(enrollmentToken) === agent.enrollmentHash, 401, 'Invalid, expired, or used enrollment credential');
    const ttl = this.ttl(ttlSeconds, this.state.policy.maxIdentitySeconds);
    const session = {id:randomUUID(), agentId, ...this.agentAddress(agentIp, agentPort), expiresAt:this.clock()+ttl, revoked:false};
    this.state.sessions[session.id] = session;
    agent.enrollmentUsed = true;
    this.event('identity.issued', {agentId, sessionId:session.id, expiresAt:session.expiresAt});
    return this.identityResponse(session);
  }
  identityResponse(session) {
    const spiffeId = `spiffe://pmbu.demo/agents/${session.agentId}/instances/${session.id}`;
    const address = this.agentAddress(session.agentIp, session.agentPort);
    return {agentId:session.agentId, sessionId:session.id, spiffeId, ...address, expiresAt:session.expiresAt,
      token:this.sign({kind:'identity', aud:'pmbu-activity-service', sub:spiffeId, agentId:session.agentId,
        sessionId:session.id, ...address, exp:session.expiresAt})};
  }
  sign(claims) {
    const head = json64({alg:'EdDSA', typ:'JWT', kid:'pmbu-demo-1'});
    const body = json64({iss:'pmbu-local-demo', iat:this.clock(), jti:randomUUID(), ...claims});
    const input = head + '.' + body;
    return input + '.' + sign(null, Buffer.from(input), this.state.privateKey).toString('base64url');
  }
  validate(token, kind) {
    try {
      requireThat(typeof token === 'string' && token.length <= 12000, 401, 'Invalid token');
      const parts = token.split('.');
      requireThat(parts.length === 3, 401, 'Invalid token');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
      requireThat(header.alg === 'EdDSA' && header.kid === 'pmbu-demo-1', 401, 'Invalid token header');
      requireThat(verify(null, Buffer.from(parts.slice(0,2).join('.')), this.state.publicKey,
        Buffer.from(parts[2], 'base64url')), 401, 'Invalid signature');
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
      const audience = kind === 'identity' ? 'pmbu-activity-service' : 'pmbu-connectivity-service';
      requireThat(claims.kind === kind && claims.iss === 'pmbu-local-demo' && claims.aud === audience &&
        Number.isInteger(claims.exp) && claims.exp > this.clock() && claims.iat <= this.clock(), 401, 'Expired or wrong-purpose token');
      const agent = this.state.agents[claims.agentId];
      const session = this.state.sessions[claims.sessionId];
      requireThat(agent && agent.status === 'active' && session && session.agentId === agent.id &&
        !session.revoked && session.expiresAt > this.clock(), 401, 'Identity is inactive');
      if (kind === 'identity') requireThat(claims.exp === session.expiresAt, 401, 'Identity superseded by renewal');
      if (kind === 'activity') {
        const grant = this.state.activities[claims.activityId];
        requireThat(grant && !grant.ended && grant.sessionId === session.id && grant.expiresAt > this.clock(), 401, 'Activity is inactive');
      }
      return {claims, agent, session};
    } catch (error) {
      if (error instanceof ServiceError) throw error;
      throw new ServiceError(401, 'Malformed token');
    }
  }
  renew(token, {ttlSeconds}) {
    const {session} = this.validate(token, 'identity');
    session.expiresAt = Math.min(this.clock()+this.ttl(ttlSeconds, this.state.policy.maxIdentitySeconds),session.sourceExpiresAt ?? Infinity);
    this.event('identity.renewed', {agentId:session.agentId, sessionId:session.id, expiresAt:session.expiresAt});
    return this.identityResponse(session);
  }
  endIdentity(token) {
    const {session} = this.validate(token, 'identity');
    session.revoked = true;
    this.event('identity.ended', {agentId:session.agentId, sessionId:session.id});
    return {ended:true};
  }
  issueActivity(token, {operation, context, flowId, ttlSeconds}) {
    const {agent, session, claims} = this.validate(token, 'identity');
    requireThat(CONTEXTS.includes(context), 400, 'Unknown network context');
    requireThat(typeof flowId === 'string' && /^[a-zA-Z0-9._:-]{1,100}$/.test(flowId), 400, 'Invalid flowId');
    const trafficClass = this.state.policy.rules[agent.profile]?.[operation];
    requireThat(trafficClass && Object.hasOwn(CLASSES, trafficClass), 403, 'Operation is not authorized for this profile');
    const expiresAt = Math.min(session.expiresAt, this.clock()+this.ttl(ttlSeconds, this.state.policy.maxActivitySeconds));
    const grant = {id:randomUUID(), agentId:agent.id, sessionId:session.id, operation, context, flowId, trafficClass,
      policyVersion:this.state.policy.version, expiresAt, ended:false};
    this.state.activities[grant.id] = grant;
    this.event('activity.issued', {agentId:agent.id, activityId:grant.id, operation, trafficClass, context, flowId});
    return {activityId:grant.id, trafficClass, expiresAt, token:this.sign({kind:'activity', aud:'pmbu-connectivity-service',
      sub:claims.sub, agentId:agent.id, sessionId:session.id, activityId:grant.id, operation, context, flowId, exp:expiresAt})};
  }
  endActivity(token) {
    const {claims} = this.validate(token, 'activity');
    this.state.activities[claims.activityId].ended = true;
    this.event('activity.ended', {agentId:claims.agentId, activityId:claims.activityId});
    return {ended:true};
  }
  evaluate(token, {context, flowId}) {
    try { return this.evaluateCurrent(token, {context, flowId}); }
    catch (error) {
      this.event('gateway.denied', {context:typeof context === 'string' ? context.slice(0,100) : 'invalid',
        flowId:typeof flowId === 'string' ? flowId.slice(0,100) : 'invalid', reason:error.message});
      throw error;
    }
  }
  evaluateCurrent(token, {context, flowId}) {
    const {claims, agent} = this.validate(token, 'activity');
    requireThat(claims.context === context && claims.flowId === flowId, 403, 'Grant does not match network context and flow');
    // Always read current policy; the priority cached at issuance is only informational.
    const trafficClass = this.state.policy.rules[agent.profile]?.[claims.operation];
    requireThat(trafficClass && Object.hasOwn(CLASSES, trafficClass), 403, 'Operation no longer authorized');
    const decision = {allow:true, agentId:agent.id, activityId:claims.activityId, operation:claims.operation,
      context, flowId, trafficClass, ...CLASSES[trafficClass], policyVersion:this.state.policy.version,
      validUntil:Math.min(claims.exp, this.state.sessions[claims.sessionId].expiresAt),
      enforcement:'application-queue-demo', cellular:'operator mapping required'};
    this.event('gateway.allowed', decision);
    return decision;
  }
  replaceRules(next) {
    requireThat(next && typeof next === 'object' && !Array.isArray(next), 400, 'rules must be an object');
    requireThat(Object.keys(next).sort().join(',') === 'health,recipe,security,travel', 400, 'Keep the four supported profiles');
    for (const operations of Object.values(next)) {
      requireThat(operations && typeof operations === 'object' && !Array.isArray(operations), 400, 'Invalid operations');
      for (const [operation, value] of Object.entries(operations)) {
        requireThat(/^[a-z_]{1,50}$/.test(operation) && !['constructor','prototype','__proto__'].includes(operation) &&
          Object.hasOwn(CLASSES, value), 400, 'Invalid operation or traffic class');
      }
    }
    this.state.policy.rules = structuredClone(next);
    this.state.policy.version++;
    this.event('policy.updated', {version:this.state.policy.version});
    return this.state.policy;
  }
  feedback({agentId, kind, detail}) {
    requireThat(this.state.agents[agentId], 404, 'Unknown agent');
    requireThat(['observation','policy_violation'].includes(kind), 400, 'Invalid feedback kind');
    requireThat(typeof detail === 'string' && detail.length > 0 && detail.length <= 500, 400, 'Invalid feedback detail');
    this.event('monitor.' + kind, {agentId, detail});
    // Feedback alone cannot establish a violation. An administrator decides suspension.
    return {recorded:true, status:this.state.agents[agentId].status, action:'administrator review'};
  }
  snapshot() {
    return {agents:Object.values(this.state.agents).map(a=>this.publicAgent(a)), policy:this.state.policy,
      identities:Object.values(this.state.sessions).map(s=>({...s, active:!s.revoked && s.expiresAt > this.clock() &&
        this.state.agents[s.agentId].status === 'active'})),
      activities:Object.values(this.state.activities).map(a=>({...a, active:!a.ended && a.expiresAt > this.clock() &&
        !this.state.sessions[a.sessionId].revoked && this.state.sessions[a.sessionId].expiresAt > this.clock() &&
        this.state.agents[a.agentId].status === 'active'})), audit:this.state.audit, now:this.clock(),
      integrations:{identity:'Local Ed25519 issuer with SPIFFE-shaped IDs; not SPIRE or an SVID implementation',
        enterprise:'Duo-style policy administration; no live Duo calls', connectivity:'Local HTTP decision service and application scheduler; no packet QoS'}};
  }
}
