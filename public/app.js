const $ = id => document.getElementById(id);
let activityToken = '';
let policyDirty = false;
let networkRequestPending = false;
function notice(message, error = false) { $('notice').textContent=message; $('notice').className=error?'error':''; }
async function api(route, body, token = $('admin-key').value, method = body === undefined ? 'GET' : 'POST') {
  const response = await fetch(route,{method,headers:{Authorization:`Bearer ${token}`,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error_description || data.error || 'Request failed');
  return data;
}
function cell(row,text) { const td=document.createElement('td'); td.textContent=text; row.append(td); return td; }
function pill(value) { const span=document.createElement('span'); span.className='pill '+value; span.textContent=value; return span; }
function action(id, task) {
  $(id).addEventListener('click',async()=>{
    $(id).disabled=true;
    try { await task(); } catch(error) { notice(error.message,true); }
    finally { $(id).disabled=false; }
  });
}
async function refresh() {
  const data=await api('/v1/admin/snapshot');
  $('connection-state').textContent='Connected';
  $('agent-count').textContent=data.agents.length;
  $('identity-count').textContent=data.identities.filter(i=>i.active).length;
  $('activity-count').textContent=data.activities.filter(i=>i.active).length;
  $('policy-version').textContent=data.policy.version;
  if (!policyDirty) $('policy-rules').value=JSON.stringify(data.policy.rules,null,2);
  $('network-controls').hidden=!data.networkControls?.available;
  $('simulator-approval').hidden=data.networkControls?.duoMode!=='simulator';
  $('network-mode').textContent=data.networkControls?.pcfEnabled?'PCF enabled: these buttons send policy requests to the lab.':'PCF disabled: these buttons issue dry-run authorizations only.';
  $('agent-rows').replaceChildren();
  for (const agent of data.agents.slice().reverse()) {
    const row=document.createElement('tr');
    const label=cell(row,agent.name); const small=document.createElement('small');
    small.textContent=agent.deviceId+' · '+agent.id; label.append(small);
    cell(row,agent.profile); cell(row,'').append(pill(agent.status)); const actions=cell(row,'');
    if (agent.status !== 'revoked') for (const status of ['suspended','revoked']) {
      const button=document.createElement('button');button.className='secondary';button.textContent=status==='revoked'?'Revoke':'Suspend';
      button.disabled=agent.status===status;
      button.addEventListener('click',async()=>{
        try { await api(`/v1/admin/agents/${agent.id}/status`,{status});await refresh();notice(`${agent.name}: ${status}`); }
        catch(error) {notice(error.message,true);}
      }); actions.append(button);
    }
    if(data.networkControls?.available && agent.status==='active' && ['health','security'].includes(agent.profile)) {
      for(const [activity,label] of [['alert','Start alert'],['background','Resume background updates']]) {
        const button=document.createElement('button');button.textContent=label;button.dataset.networkActivity='true';button.disabled=networkRequestPending;
        button.addEventListener('click',async()=>{
          if(networkRequestPending)return;
          networkRequestPending=true;
          document.querySelectorAll('[data-network-activity]').forEach(b=>b.disabled=true);
          try {
            const result=await api(`/v1/admin/agents/${agent.id}/activity`,{
              action:activity,identityToken:$('identity-token').value.trim(),approvalId:$('network-approval').value.trim(),
              context:$('context').value,flowId:$('flow-id').value.trim(),destinationIp:$('network-destination').value.trim(),
              destinationPort:Number($('network-port').value),protocol:$('network-protocol').value,
              subscriberId:$('network-subscriber').value.trim(),pduSessionId:$('network-pdu').value.trim()
            });
            const detail=result.authorization_details[0];
            $('network-result').textContent=JSON.stringify({agent:agent.name,operation:detail.operation,qosTier:detail.qos_tier,
              flow:detail.flow,expiresIn:result.expires_in,pcf:result.pcf||{status:'dry_run_only'}},null,2);
            await refresh();notice(result.pcf?`PCF accepted ${result.pcf.policy} for ${agent.name}.`:`Dry-run activity authorized: ${detail.qos_tier}.`);
          }catch(error){$('network-result').textContent='Request failed: '+error.message;notice(error.message,true);}
          finally{networkRequestPending=false;document.querySelectorAll('[data-network-activity]').forEach(b=>b.disabled=false);}
        });actions.append(button);
      }
    }
    $('agent-rows').append(row);
  }
  $('audit-events').replaceChildren();
  for (const event of data.audit.slice(-30).reverse()) {
    const div=document.createElement('div');div.className='event';
    const title=document.createElement('b');title.textContent=event.type;
    const time=document.createElement('span');time.textContent=new Date(event.at*1000).toLocaleTimeString();
    const detail=document.createElement('div');const {id,at,type,...rest}=event;detail.textContent=JSON.stringify(rest);
    div.append(title,time,detail);$('audit-events').append(div);
  }
}
action('connect',async()=>{await refresh();notice('Connected to local identity service.');});
action('refresh',refresh);
action('run-demo',async()=>{
  const result=await api('/v1/demo',{context:$('context').value});
  $('demo-results').hidden=false;$('demo-mode').textContent=result.mode;
  $('dispatch-rows').replaceChildren();
  for (const decision of result.dispatched) {
    const row=document.createElement('tr');cell(row,decision.dispatchOrder);cell(row,decision.arrival+1);
    cell(row,decision.operation);cell(row,'').append(pill(decision.trafficClass));cell(row,decision.dscp);cell(row,decision.context);
    $('dispatch-rows').append(row);
  }
  $('demo-checks').replaceChildren();
  for (const attempt of result.attempts) {
    const node=document.createElement('div');node.className='pill';node.textContent=(attempt.blocked?'BLOCKED: ':'ALLOWED: ')+attempt.name;$('demo-checks').append(node);
  }
  for (const rejected of result.denied) {
    const node=document.createElement('div');node.className='pill revoked';node.textContent='DENIED: '+rejected.reason;$('demo-checks').append(node);
  }
  await refresh();notice('Scenario complete. Dispatch order is real application scheduling; network treatment is an integration intent.');
});
$('registration').addEventListener('submit',async event=>{
  event.preventDefault();
  try {
    const registration=await api('/v1/admin/agents',Object.fromEntries(new FormData(event.target)));
    const identity=await api('/v1/identities',{agentId:registration.agent.id},registration.enrollmentToken);
    $('identity-token').value=identity.token;$('credential-output').textContent=JSON.stringify(identity,null,2);
    await refresh();notice('Agent registered. Identity valid for up to ten minutes.');
  } catch(error) {notice(error.message,true);}
});
$('activity-form').addEventListener('submit',async event=>{
  event.preventDefault();
  try {
    const grant=await api('/v1/activities',{operation:$('operation').value,context:$('context').value,flowId:$('flow-id').value},$('identity-token').value);
    activityToken=grant.token;$('credential-output').textContent=JSON.stringify(grant,null,2);
    await refresh();notice(`Authorized activity: ${grant.trafficClass}`);
  }catch(error){notice(error.message,true);}
});
action('renew',async()=>{
  const identity=await api('/v1/identities/renew',{},$('identity-token').value);
  $('identity-token').value=identity.token;$('credential-output').textContent=JSON.stringify(identity,null,2);await refresh();notice('Identity renewed.');
});
action('end-identity',async()=>{await api('/v1/identities/end',{},$('identity-token').value);await refresh();notice('Identity ended; its activity grants are inactive.');});
action('end-activity',async()=>{await api('/v1/activities/end',{},activityToken);await refresh();notice('Activity ended.');});
$('policy-rules').addEventListener('input',()=>{policyDirty=true;});
action('save-policy',async()=>{await api('/v1/admin/policy',{rules:JSON.parse($('policy-rules').value)},undefined,'PUT');policyDirty=false;await refresh();notice('Policy saved. Request a new agent activity to apply it through PCF.');});

action('request-network-approval',async()=>{
  const push=await api('/duo/push',{},$('identity-token').value.trim());
  $('network-approval').value=push.id;
  $('network-result').textContent=JSON.stringify({status:push.status,agentIp:push.agentIp,agentPort:push.agentPort,expiresAt:push.expiresAt},null,2);
  notice('Simulator approval requested. Review the agent address, then approve as admin.');
});
action('approve-network-request',async()=>{
  await api('/duo/admin/decide',{push_id:$('network-approval').value.trim(),status:'approved'});
  notice('Simulator approval granted. Choose an activity beside the matching agent.');
});
