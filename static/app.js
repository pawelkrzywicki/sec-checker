const $=id=>document.getElementById(id), csrf=document.querySelector('meta[name=csrf-token]').content;
let items=[],selected=new Set(),timer;
async function api(path,body){const options={};if(body){options.method='POST';options.headers={'X-CSRF-Token':csrf};if(body instanceof FormData)options.body=body;else{options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}}const r=await fetch(path,options);const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;}
function message(text){$('message').textContent=text;}
function filtered(){const q=$('search').value.toLowerCase();return items.filter(x=>x.host.includes(q));}
function render(){const fragment=document.createDocumentFragment();for(const item of filtered()){const label=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.checked=selected.has(item.host);box.onchange=()=>{box.checked?selected.add(item.host):selected.delete(item.host);$('reviewed').checked=false;count();};label.append(box,document.createTextNode(item.host));if(item.saved_login||item.login_page_hint){const tag=document.createElement('span');tag.className='hint';tag.textContent=item.saved_login?'STORED PASSWORD':'LOGIN HINT';label.append(tag);}fragment.append(label);}$('domains').replaceChildren(fragment);count();}
function count(){$('selected').textContent=selected.size+' selected';$('domain-count').textContent=items.length+' DOMAINS';}
$('upload-form').onsubmit=async e=>{e.preventDefault();$('upload').disabled=true;message('Importing locally and removing the raw upload…');try{const data=await api('/api/upload',new FormData(e.target));items=data.items;selected.clear();lastResults=[];resultMode='all';$('result-search').value='';$('reviewed').checked=false;$('review').hidden=false;$('findings').hidden=true;render();$('history').value='';$('logins').value='';message('Imported '+data.entries.toLocaleString()+' entries. '+data.excluded_entries.toLocaleString()+' adult-domain entries filtered. '+data.saved_login_domains+' domains have stored-password entries. Review your selection before scanning.');}catch(e){message(e.message);}finally{$('upload').disabled=false;}};
$('search').oninput=render;
$('stored').onclick=()=>{items.filter(x=>x.saved_login).forEach(x=>selected.add(x.host));$('reviewed').checked=false;render();};
$('hints').onclick=()=>{items.filter(x=>x.login_page_hint).forEach(x=>selected.add(x.host));$('reviewed').checked=false;render();};
$('select-all').onclick=()=>{items.forEach(x=>selected.add(x.host));$('reviewed').checked=false;render();};
$('visible').onclick=()=>{filtered().forEach(x=>selected.add(x.host));$('reviewed').checked=false;render();};
$('none').onclick=()=>{selected.clear();$('reviewed').checked=false;render();};
$('scan').onclick=async()=>{if(!selected.size||!$('reviewed').checked){message('Select sites and confirm you excluded sensitive domains.');return;}try{await api('/api/scan',{hosts:[...selected],reviewed:true});$('scan').disabled=true;$('upload').disabled=true;$('cancel').disabled=false;$('findings').hidden=false;clearInterval(timer);timer=setInterval(poll,1500);poll();}catch(e){message(e.message);}};
$('cancel').onclick=async()=>{try{const data=await api('/api/cancel',{});message(data.message);}catch(e){message(e.message);}};
$('clear').onclick=async()=>{try{await api('/api/clear',{});items=[];selected.clear();lastResults=[];resultMode='all';$('result-search').value='';render();$('review').hidden=true;$('findings').hidden=true;$('results').replaceChildren();message('Imported data and results cleared from this session.');}catch(e){message(e.message);}};
let lastResults=[],resultMode='all';
function setResultFilter(mode){resultMode=mode;drawResults();}
for(const mode of ['all','investigation','incomplete']) $('filter-'+mode).onclick=()=>setResultFilter(mode);
$('result-search').oninput=drawResults;
function drawResults(){
  const query=$('result-search').value.toLowerCase();
  const shown=lastResults.filter(r=>(resultMode==='all'||(resultMode==='investigation'?r.needs_investigation:r.incomplete))&&r.host.toLowerCase().includes(query));
  for(const mode of ['all','investigation','incomplete']) $('filter-'+mode).setAttribute('aria-pressed',String(resultMode===mode));
  for(const link of document.querySelectorAll('.downloads a')) link.href='/api/report/'+link.getAttribute('href').split('/').pop().split('?')[0]+'?filter='+resultMode+'&q='+encodeURIComponent(query);
  $('result-count').textContent='Showing '+shown.length+' of '+lastResults.length+' results'+(resultMode==='investigation'?' · Only flagged sites':resultMode==='incomplete'?' · Checks that could not finish completely':'')+'.';
  const frag=document.createDocumentFragment();
  for(const r of shown){
    const tr=document.createElement('tr');if(r.needs_investigation)tr.className='flagged';
    const host=document.createElement('td');host.textContent=r.host;if(r.needs_investigation){const marker=document.createElement('small');marker.className='row-flag';marker.textContent='Needs investigation';host.append(marker);}
    const account=document.createElement('td');account.textContent=r.saved_login?'Stored password entry':'No stored entry supplied';
    const tls=document.createElement('td'),provider=document.createElement('strong'),issuer=document.createElement('small'),tlsState=document.createElement('small');
    provider.textContent=r.certificate?.provider||'Issuer unavailable';issuer.textContent=r.certificate?.issuer||'';tlsState.textContent=r.tls;tls.append(provider,issuer,tlsState);
    const php=document.createElement('td'),evidence=document.createElement('small');php.textContent=r.php.status;evidence.textContent=r.php.evidence;php.append(evidence);
    const review=document.createElement('td');
    for(const finding of r.findings||[]){
      const box=document.createElement('div'),badge=document.createElement('span'),title=document.createElement('strong'),why=document.createElement('small'),action=document.createElement('small');
      box.className='finding';badge.className='severity '+finding.severity.toLowerCase();badge.textContent=finding.severity;title.textContent=finding.title;why.textContent=finding.reason;action.textContent='Next step: '+finding.action;
      box.append(badge,title,why,action);
      if(finding.advisory){const link=document.createElement('a');link.href=finding.advisory;link.target='_blank';link.rel='noreferrer';link.textContent='Read advisory ↗';box.append(link);}
      review.append(box);
    }
    if(!r.needs_investigation){const note=document.createElement('small');note.textContent=r.incomplete?'Check incomplete: '+(r.error||'Full certificate chain unavailable.')+' Retry or confirm with the operator. This is not a confirmed vulnerability.':'No flagged evidence from these checks. Hidden software versions and server configuration may still be unknown.';review.append(note);}
    tr.append(host,account,tls,php,review);frag.append(tr);
  }
  if(!shown.length){const row=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=5;cell.className='empty-results';cell.textContent='No results match this filter.';row.append(cell);frag.append(row);}
  $('results').replaceChildren(frag);
  const risk=lastResults.filter(r=>r.needs_investigation).length,unknown=lastResults.filter(r=>r.php_unknown).length,incomplete=lastResults.filter(r=>r.incomplete).length;
  $('summary').replaceChildren();
  for(const [value,label,mode] of [[lastResults.length,'Sites checked','all'],[risk,'Need investigation','investigation'],[incomplete,'Incomplete checks','incomplete'],[unknown,'PHP version unknown',null]]){
    const card=document.createElement(mode?'button':'div'),number=document.createElement('strong');card.className='stat'+(mode?' stat-button':'');number.textContent=value;card.append(number,document.createTextNode(label));
    if(mode){card.setAttribute('aria-pressed',String(resultMode===mode));card.onclick=()=>setResultFilter(mode);}
    $('summary').append(card);
  }
}
async function poll(){try{
  const state=await api('/api/status');lastResults=state.results;
  $('progress').max=state.total||1;$('progress').value=state.done;
  message(state.done+' / '+state.total+' checked'+(state.queued?' · Waiting for scan capacity…':state.running?'…':state.cancelled?' · Stopped.':' · Complete.')+(state.error?' '+state.error:''));drawResults();
  if(!state.running){clearInterval(timer);$('scan').disabled=false;$('upload').disabled=false;$('cancel').disabled=true;}
}catch(e){clearInterval(timer);$('scan').disabled=false;$('upload').disabled=false;$('cancel').disabled=true;message(e.message);}}

// Restore only this browser session’s workspace after reload or worker changes.
api('/api/inventory').then(data=>{items=data.items;if(items.length){$('review').hidden=false;render();}return api('/api/status');}).then(state=>{if(state.total){$('findings').hidden=false;poll();if(state.running){$('scan').disabled=true;$('upload').disabled=true;$('cancel').disabled=false;timer=setInterval(poll,1500);}}}).catch(e=>message(e.message));
