"""Editable diagrams.net and SVG architecture views, using only the Python stdlib."""
from pathlib import Path
from html import escape
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'architecture'
OUT.mkdir(parents=True, exist_ok=True)
P = {'ink':'#16324b','muted':'#60778b','line':'#cbd7e2','prototype':'#e2f5ef','prototype_stroke':'#238571',
     'planned':'#fff4df','planned_stroke':'#b78228','lab':'#e8f0fb','lab_stroke':'#708aad',
     'control':'#7759ac','data':'#2180be','feedback':'#27866d'}
class View:
    def __init__(self, name, slug, w, h):
        self.name,self.slug,self.w,self.h=name,slug,w,h
        self.nodes=[];self.edges=[];self.labels=[];self.texts=[]
    def text(self,x,y,lines,size=20,color=None,bold=False):
        self.texts.append((x,y,lines,size,color or P['ink'],bold))
    def node(self,id,x,y,w,h,title,lines=(),kind='prototype',container=False):
        self.nodes.append(dict(id=id,x=x,y=y,w=w,h=h,title=title,lines=lines,kind=kind,container=container))
    def edge(self,src,dst,points,color='control',dashed=False,label=None,at=None):
        self.edges.append(dict(src=src,dst=dst,points=points,color=P.get(color,color),dashed=dashed))
        if label:self.labels.append((*at,label,P.get(color,color)))
    def svg(self):
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}">',
           '<defs>']
        for color in set(e['color'] for e in self.edges):
            s.append(f'<marker id="a{color[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{color}"/></marker>')
        s+=['</defs>','<rect width="100%" height="100%" fill="#f7f9fc"/>']
        def text(x,y,lines,size,color,bold=False):
            parts=[f'<text x="{x}" y="{y}" font-family="Arial, sans-serif" font-size="{size}" fill="{color}" font-weight="{700 if bold else 400}">']
            for i,line in enumerate(lines):parts.append(f'<tspan x="{x}" dy="{0 if i==0 else size*1.4}">{escape(line)}</tspan>')
            return ''.join(parts)+'</text>'
        for n in self.nodes:
            if not n['container']:continue
            s.append(f'<rect x="{n["x"]}" y="{n["y"]}" width="{n["w"]}" height="{n["h"]}" rx="20" fill="#ffffff" stroke="{P["line"]}" stroke-width="2"/>')
            s.append(text(n['x']+24,n['y']+38,[n['title']],22,P['ink'],True))
            s.append(text(n['x']+24,n['y']+66,n['lines'],17,P['muted']))
        for e in self.edges:
            coords=' '.join(f'{x},{y}' for x,y in e['points'])
            dash=' stroke-dasharray="9 6"' if e['dashed'] else ''
            s.append(f'<polyline points="{coords}" fill="none" stroke="{e["color"]}" stroke-width="3"{dash} marker-end="url(#a{e["color"][1:]})" stroke-linejoin="round"/>')
        for n in self.nodes:
            if n['container']:continue
            s.append(f'<rect x="{n["x"]}" y="{n["y"]}" width="{n["w"]}" height="{n["h"]}" rx="14" fill="{P[n["kind"]]}" stroke="{P[n["kind"]+"_stroke"]}" stroke-width="2"/>')
            s.append(text(n['x']+20,n['y']+34,[n['title']],22,P['ink'],True))
            s.append(text(n['x']+20,n['y']+65,n['lines'],18,P['ink']))
        for x,y,label,color in self.labels:
            # A white halo keeps connector labels readable without hiding junctions.
            s.append(f'<text x="{x}" y="{y}" font-family="Arial, sans-serif" font-size="17" fill="{color}" stroke="#f7f9fc" stroke-width="6" paint-order="stroke">{escape(label)}</text>')
        for x,y,lines,size,color,bold in self.texts:s.append(text(x,y,lines,size,color,bold))
        s.append('</svg>');(OUT/(self.slug+'.svg')).write_text('\n'.join(s))
    def xml(self, parent):
        d=ET.SubElement(parent,'diagram',id=self.slug,name=self.name)
        model=ET.SubElement(d,'mxGraphModel',dx=str(self.w),dy=str(self.h),grid='1',gridSize='10',guides='1',tooltips='1',connect='1',arrows='1',fold='1',page='1',pageScale='1',pageWidth=str(self.w),pageHeight=str(self.h),math='0',shadow='0')
        r=ET.SubElement(model,'root');ET.SubElement(r,'mxCell',id='0');ET.SubElement(r,'mxCell',id='1',parent='0')
        lookup={n['id']:n for n in self.nodes}
        for n in self.nodes:
            fill='#ffffff' if n['container'] else P[n['kind']]
            stroke=P['line'] if n['container'] else P[n['kind']+'_stroke']
            value=f'<b style="font-size:22px">{escape(n["title"])}</b>' + ''.join('<br>'+escape(line) for line in n['lines'])
            style=f'rounded=1;whiteSpace=wrap;html=1;align=left;verticalAlign=top;spacingLeft=20;spacingTop=15;fontSize=18;fontFamily=Arial;fontColor={P["ink"]};fillColor={fill};strokeColor={stroke};strokeWidth=2;'
            c=ET.SubElement(r,'mxCell',id=n['id'],value=value,style=style,vertex='1',parent='1')
            ET.SubElement(c,'mxGeometry',x=str(n['x']),y=str(n['y']),width=str(n['w']),height=str(n['h']),attrib={'as':'geometry'})
        for i,e in enumerate(self.edges):
            src,dst=lookup[e['src']],lookup[e['dst']]
            start,end=e['points'][0],e['points'][-1]
            ports=f'exitX={(start[0]-src["x"])/src["w"]};exitY={(start[1]-src["y"])/src["h"]};entryX={(end[0]-dst["x"])/dst["w"]};entryY={(end[1]-dst["y"])/dst["h"]};exitPerimeter=0;entryPerimeter=0;'
            style=f'edgeStyle=segmentEdgeStyle;html=1;rounded=0;endArrow=block;endFill=1;strokeColor={e["color"]};strokeWidth=3;dashed={int(e["dashed"])};{ports}'
            c=ET.SubElement(r,'mxCell',id='edge'+str(i),edge='1',parent='1',source=e['src'],target=e['dst'],style=style)
            g=ET.SubElement(c,'mxGeometry',relative='1',attrib={'as':'geometry'});a=ET.SubElement(g,'Array',attrib={'as':'points'})
            for x,y in e['points'][1:-1]:ET.SubElement(a,'mxPoint',x=str(x),y=str(y))
        texts=list(self.texts)+[(x,y,[label],17,color,False) for x,y,label,color in self.labels]
        for i,(x,y,lines,size,color,bold) in enumerate(texts):
            value='<br>'.join(escape(line) for line in lines)
            if bold:value='<b>'+value+'</b>'
            c=ET.SubElement(r,'mxCell',id='text'+str(i),vertex='1',parent='1',value=value,
                style=f'text;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontFamily=Arial;fontSize={size};fontColor={color};fillColor=none;strokeColor=none;')
            width=max(200,max((len(line) for line in lines),default=1)*size*.59)
            ET.SubElement(c,'mxGeometry',x=str(x),y=str(y-size),width=str(width),height=str(len(lines)*size*1.5+8),attrib={'as':'geometry'})

a=View('01 — Team architecture','team-architecture',2000,1290)
a.text(60,62,['Agent identity driven traffic prioritization'],38,bold=True)
a.text(60,102,['PMBU Hackfest · HF-2834 | Shared architecture and ownership | v1 · October 2, 2026'],20,P['muted'])
a.text(60,150,['TEAL = working local prototype     AMBER = planned integration     BLUE = supplied lab infrastructure'],18,P['muted'])
a.node('endpoints',60,190,500,670,'LOCAL AGENTS', ['Owner: local-agent teammate'],container=True)
a.node('agents',90,285,440,165,'Activity changes importance', ['Health: model update → background','Health: synthetic alert → critical','Travel: booking → interactive','Recipe: recipe fetch → background'])
a.node('binder',90,540,440,145,'Trusted flow binding', ['Proxy / sidecar or OS flow association','Bind agent identity to observed traffic','Planned; flowId is a logical label today'],'planned')
a.node('devices',90,725,440,95,'Device targets', ['Phone · Raspberry Pi · laptop · Mac mini'],'planned')
a.node('identity',650,190,590,670,'IDENTITY + ENTERPRISE POLICY', ['Owner: Arindam | local service :4180'],container=True)
a.node('registry',680,285,530,160,'Agent registry and accountable owner', ['Administrator assigns profile and device','Single-use bootstrap: ≤ 5 minutes','Duo / enterprise approval: future adapter'])
a.node('runtime',680,490,530,145,'Temporary runtime identity', ['Ed25519 JWT · SPIFFE-shaped instance ID','Issue / renew / end · TTL ≤ 10 minutes','SPIRE attestation + real SVID: future adapter'])
a.node('activity',680,680,530,140,'Activity authorization and policy', ['Identity + operation + flow + context','Activity TTL ≤ 2 minutes, parent-bounded','Profile rules assign class; revocation is online'])
a.node('connectivity',1330,190,610,670,'HOSTED CONNECTIVITY BOUNDARY', ['Owner: connectivity / network teammate'],container=True)
a.node('gateway',1360,285,550,185,'Online gateway authorization', ['Verify activity token, expiry and lifecycle','Match flow ID and network context','Reevaluate current policy at enforcement','Local HTTP gateway + application scheduler'])
a.node('adapters',1360,570,550,250,'Deployment-specific enforcement', ['Access / cellular → PCF adapter + core QoS','Edge DC → proxy / host / fabric queues','Enterprise → branch / central QoS queues','','Planned: real packet / network treatment','DSCP is intent; no automatic 5QI mapping'],'planned')
a.edge('agents','runtime',[(530,385),(605,385),(605,562),(680,562)],label=None)
a.edge('binder','activity',[(530,615),(580,615),(580,748),(680,748)],dashed=True,label=None)
a.edge('activity','gateway',[(1210,748),(1280,748),(1280,375),(1360,375)],label=None)
a.text(562,480,['1. Identity'],14,P['control'])
a.text(562,715,['2. Activity'],14,P['control'])
a.text(1248,510,['3. Validate','+ decide'],14,P['control'])
a.edge('agents','binder',[(310,450),(310,540)],dashed=True)
a.edge('gateway','adapters',[(1635,470),(1635,570)],dashed=True,label='4. Class → deployment policy',at=(1435,525))
a.edge('adapters','activity',[(1580,820),(1580,900),(945,900),(945,820)],color='feedback',dashed=True,label='5. Behavior feedback → review; no automatic downgrade',at=(950,930))
a.text(60,960,['TEAM DELIVERABLES'],20,bold=True)
roles=[('Identity / policy','Registry, grants, lifecycle','HTTP contract + audit'),('Local agents','Runtime identity client','Model update / alert workloads'),('Connectivity / lab','Trustworthy flow association','PCF API + QoS enforcement'),('Demo / monitoring','Congestion and queue evidence','Recording + generated transcript')]
for i,(title,l1,l2) in enumerate(roles):a.node('role'+str(i),60+i*480,990,450,130,title,[l1,l2],kind='lab')
a.text(60,1170,['Implemented: local authorization and application queue ordering. Live Duo, SPIRE and network QoS remain integration work.'],19,P['muted'])
a.text(60,1202,['Tokens are bearer credentials. Alert intent is authorized, not clinically validated. Lab access is pending teammate provisioning.'],19,P['muted'])
a.text(60,1250,['Second page: exact mapping to the supplied cellular lab, with addresses and interfaces retained.'],19,P['control'])

b=View('02 — Cellular lab integration','cellular-lab-integration',2200,1490)
b.text(50,62,['Cellular lab integration — proposed target placement'],38,bold=True)
b.text(50,105,['Based on teammate setup screenshot | Addresses retained as supplied; availability and API behavior are unverified'],20,P['muted'])
b.text(50,150,['BLUE = supplied lab     TEAL = local prototype     AMBER / DASHED = proposed deployment or integration'],18,P['muted'])
b.node('idservice',50,200,660,160,'Your Agent Identity Management service', ['Runs locally today · http://127.0.0.1:4180','Registry · runtime identities · activity policy · audit','Deploy location after access: confirm with team'])
b.node('cc',810,200,450,160,'CC / UDR', ['Supplied lab component','Existing link to core; interface not labeled'],'lab')
b.node('endpoint',50,430,450,580,'ENDPOINT / LATTICE HOST', ['10.8.102.55 · supplied lab'],container=True)
b.node('agent1',80,530,180,105,'Agent 1', ['Model update','Synthetic alert'],'planned')
b.node('agent2',285,530,185,105,'Agent 2', ['Recipe / travel','Demo workload'],'planned')
b.node('flowbinding',80,675,390,115,'Identity ↔ observed flow', ['Planned proxy / sidecar binding','Context + subscriber + flow association'],'planned')
b.node('lattice',80,825,390,120,'lattice', ['Supplied endpoint component','Exact UE / RAN role: confirm'],'lab')
b.node('core',570,430,780,580,'5G CORE', ['10.8.102.208 · supplied lab'],container=True)
b.node('amf',610,590,170,115,'AMF', ['Access / mobility'],'lab')
b.node('smf',900,500,190,120,'SMF', ['Session control'],'lab')
b.node('pcf',900,695,190,120,'PCF', ['Policy control'],'lab')
b.node('upf',1130,825,180,120,'UPF', ['User-plane flows'],'lab')
b.node('aicloud',1440,430,700,280,'AI CLOUD / CONNECTIVITY INTEGRATION HOST', ['10.8.102.52 · supplied lab host; new service placement is proposed'],container=True)
b.node('hosted',1470,535,300,135,'Connectivity decision', ['Gateway auth + flow context','Validate /v1/gateway/evaluate','Local today; deploy after access'],'planned')
b.node('pcfadapter',1800,535,310,135,'PCF integration adapter', ['Map class → supported QoS','Lab API + credentials: TBD','NEF / AF route: confirm'],'planned')
b.node('router',1510,825,240,120,'Lab router', ['Routing / connectivity','QoS support: confirm'],'lab')
b.node('internet',1850,825,290,120,'Internet services', ['Synthetic alerts / booking','Recipes / model updates'],'lab')
b.node('ise',720,1130,320,145,'ISE', ['10.8.95.13','RADIUS shown in supplied setup','Keep separate from agent issuer'],'lab')
b.edge('idservice','hosted',[(600,360),(600,378),(1375,378),(1375,600),(1470,600)],dashed=True,label='Identity + current policy / online authorization',at=(740,372))
b.edge('hosted','pcfadapter',[(1770,603),(1800,603)],dashed=True)
b.edge('pcfadapter','pcf',[(1955,670),(1955,760),(1390,760),(1390,755),(1090,755)],dashed=True,label='Proposed: use API path shown in teammate setup',at=(1440,745))
b.edge('cc','core',[(1035,360),(1035,430)],color='lab_stroke',label='Existing association',at=(1050,405))
b.edge('lattice','amf',[(470,867),(540,867),(540,645),(610,645)],label='N2',at=(552,632))
b.edge('amf','smf',[(780,645),(850,645),(850,560),(900,560)],label='N11',at=(810,547))
b.edge('pcf','smf',[(995,695),(995,620)],label='N7',at=(1015,668))
b.edge('smf','upf',[(1090,560),(1225,560),(1225,825)],label='N4',at=(1240,690))
b.edge('lattice','upf',[(470,920),(1130,920)],color='data',label='N3 · agent traffic',at=(710,902))
b.edge('upf','router',[(1310,885),(1510,885)],color='data',label='N6',at=(1390,867))
b.edge('router','internet',[(1750,885),(1850,885)],color='data')
b.edge('router','aicloud',[(1630,825),(1630,710)],color='data',label='Existing route',at=(1650,790))
b.edge('smf','ise',[(900,605),(870,605),(870,1075),(880,1075),(880,1130)],color='lab_stroke',label='RADIUS link shown; configuration TBD',at=(900,1086))
b.edge('ise','router',[(1040,1205),(1630,1205),(1630,945)],color='lab_stroke',label='Existing lab connectivity',at=(1185,1188))
b.edge('hosted','idservice',[(1470,650),(1410,650),(1410,395),(650,395),(650,360)],color='feedback',dashed=True,label='Observation / policy-violation feedback',at=(710,389))
b.edge('agent1','flowbinding',[(170,635),(170,675)],dashed=True)
b.edge('agent2','flowbinding',[(378,635),(378,675)],dashed=True)
b.edge('flowbinding','lattice',[(275,790),(275,825)],dashed=True)
b.text(50,1328,['CONFIRM WHEN ACCESS ARRIVES'],20,bold=True)
b.text(50,1362,['PCF API/auth • lattice UE/RAN role • subscriber/PDU-session mapping • supported QoS profiles • flow filters • measurable bottleneck'],19,P['muted'])
b.text(50,1394,['Private host IPs identify lab machines, not workload SPIFFE IDs or confirmed subscriber addresses. No credentials appear here.'],19,P['muted'])
b.text(50,1426,['Prototype currently authorizes and schedules application work. This is a target integration design, not a claim of live cellular QoS.'],19,P['muted'])
b.text(50,1460,['Purple: control / policy    Blue: data path    Green dashed: feedback    Crossed lines without a dot are not junctions.'],17,P['muted'])

mx=ET.Element('mxfile',host='app.diagrams.net',agent='PMBU architecture generator',version='24.7.17')
for view in [a,b]:view.svg();view.xml(mx)
ET.indent(mx)
ET.ElementTree(mx).write(OUT/'pmbu-agent-architecture.drawio',encoding='utf-8',xml_declaration=True)
print('Generated two SVG views and one editable two-page diagrams.net document.')
