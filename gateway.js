import {requireThat, CONTEXTS} from './identity.js';

export function dispatch(service, jobs) {
  requireThat(Array.isArray(jobs) && jobs.length > 0 && jobs.length <= 32, 400, 'jobs must contain 1..32 flows');
  const accepted = [], denied = [];
  for (const [arrival, job] of jobs.entries()) {
    try {
      requireThat(job && typeof job === 'object', 400, 'Invalid job');
      const decision = service.evaluate(job.token, job);
      accepted.push({arrival, job, decision});
    } catch (error) { denied.push({arrival, flowId:job?.flowId, status:error.status || 500, reason:error.message}); }
  }
  accepted.sort((a,b)=>b.decision.rank-a.decision.rank || a.arrival-b.arrival);
  const dispatched = [];
  for (const item of accepted) {
    // Enforcement uses a fresh decision rather than trusting cached JWT priority claims.
    try { dispatched.push({arrival:item.arrival, dispatchOrder:dispatched.length+1, ...service.evaluate(item.job.token, item.job)}); }
    catch (error) { denied.push({arrival:item.arrival, flowId:item.job.flowId, status:error.status || 500, reason:error.message}); }
  }
  return {mode:'Actual application-level batch scheduling; no packet marking or measured network latency', dispatched, denied};
}

export function runDemo(service, context = 'access') {
  requireThat(CONTEXTS.includes(context), 400, 'Unknown context');
  const actors = {};
  for (const profile of ['recipe','travel','health','security']) {
    const enrolled = service.register({name:`${profile} demo`, deviceId:`demo-${profile}-device`, profile});
    actors[profile] = {agent:enrolled.agent, identity:service.issueIdentity(enrolled.enrollmentToken, {agentId:enrolled.agent.id})};
  }
  const inputs = [['recipe','recipe_fetch'],['health','model_update'],['travel','booking'],['health','health_alert'],['security','security_alert']];
  const grants = inputs.map(([profile,operation], index) => {
    const flowId = `demo-${context}-${randomSuffix()}-${index}`;
    const grant = service.issueActivity(actors[profile].identity.token, {operation, context, flowId});
    return {token:grant.token, context, flowId};
  });
  const attempts = [];
  const attempt = (name, action) => {
    try { action(); attempts.push({name, blocked:false}); }
    catch (error) { attempts.push({name, blocked:true, status:error.status, reason:error.message}); }
  };
  attempt('Recipe agent requests health_alert', ()=>service.issueActivity(actors.recipe.identity.token,
    {operation:'health_alert', context, flowId:'forged-alert'}));
  attempt('Activity used on a different flow', ()=>service.evaluate(grants[3].token, {context, flowId:'different-flow'}));
  service.setStatus(actors.security.agent.id, 'revoked');
  service.feedback({agentId:actors.recipe.agent.id, kind:'observation', detail:'Demo gateway observed background recipe traffic'});
  return {context, actors:Object.fromEntries(Object.entries(actors).map(([k,v])=>[k,v.agent.id])),
    arrivals:inputs.map(([profile,operation],arrival)=>({arrival,profile,operation})),
    ...dispatch(service, grants), attempts};
}
function randomSuffix() { return Math.random().toString(36).slice(2,10); }
