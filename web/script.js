'use strict';
const PPS = (() => {
  const enc=new TextEncoder(), dec=new TextDecoder('utf-8',{fatal:true});
  const byteLength=s=>enc.encode(s).length;
  function insist(ok,msg='Invalid file format'){if(!ok)throw new Error(msg);}
  const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
  const str=(x,min,max)=>typeof x==='string'&&!x.includes('\0')&&byteLength(x)>=min&&byteLength(x)<=max;
  const keys=(o,expected)=>obj(o)&&Object.keys(o).sort().join('|')===[...expected].sort().join('|');
  function validate(data,legacy=false){
    if(!legacy)insist(keys(data,['schema','entries'])&&data.schema===2);
    const a=legacy?data:data.entries;insist(Array.isArray(a)&&a.length<=PPS_LIMITS.maxEntries);const ids=new Set();
    for(const e of a){insist(obj(e)&&str(e.site,1,128)&&str(e.login,0,256)&&str(e.password,0,256));
      if(legacy){const extras=Object.entries(e).filter(([k])=>!['site','login','password'].includes(k));insist(extras.length<=8);for(const [k,v] of extras)insist(str(k,1,64)&&str(v,0,512));}
      else {insist(keys(e,['id','site','login','password','extras'])&&typeof e.id==='string'&&/^[a-f0-9]{32}$/i.test(e.id)&&!ids.has(e.id));ids.add(e.id);insist(Array.isArray(e.extras)&&e.extras.length<=8);const names=new Set();for(const x of e.extras){insist(keys(x,['name','value'])&&str(x.name,1,64)&&str(x.value,0,512)&&!names.has(x.name));names.add(x.name);}}
    }
    insist(byteLength(JSON.stringify(data))<=PPS_LIMITS.vaultBytes,'Storage size exceeds '+(PPS_LIMITS.vaultBytes/1024)+' KiB');return data;
  }
  const hex=a=>Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');
  function unhex(s,n){insist(typeof s==='string'&&s.length===n*2&&/^[a-f0-9]+$/i.test(s));return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));}
  function b64(a){let s='';for(const x of a)s+=String.fromCharCode(x);return btoa(s);}
  function unb64(s){insist(typeof s==='string'&&s.length<=4*Math.ceil((PPS_LIMITS.vaultBytes+16)/3)&&s.length%4===0&&/^[A-Za-z0-9+/]+={0,2}$/.test(s));return Uint8Array.from(atob(s),x=>x.charCodeAt(0));}
  async function key(password,salt,iterations){const raw=enc.encode(password);try{const material=await crypto.subtle.importKey('raw',raw,'PBKDF2',false,['deriveKey']);return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}finally{raw.fill(0);}}
  async function encryptBackup(data,password){validate(data);insist(str(password,12,128),'Backup password must be 12–128 bytes long');const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),plain=enc.encode(JSON.stringify(data));try{const k=await key(password,salt,250000),cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode('PPS backup v2')},k,plain));return {format:'pps-backup',version:2,iterations:250000,salt:hex(salt),iv:hex(iv),data:b64(cipher)};}finally{plain.fill(0);}}
  async function decryptBackup(backup,password){
    insist(keys(backup,['format','version','iterations','salt','iv','data'])&&backup.format==='pps-backup'&&backup.version===2&&Number.isInteger(backup.iterations)&&backup.iterations>=120000&&backup.iterations<=1000000);
    insist(str(password,1,128));const salt=unhex(backup.salt,16),iv=unhex(backup.iv,12),cipher=unb64(backup.data);insist(cipher.length>=18&&cipher.length<=PPS_LIMITS.vaultBytes+16);let plain;
    try{const k=await key(password,salt,backup.iterations);plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:enc.encode('PPS backup v2')},k,cipher));return validate(JSON.parse(dec.decode(plain)));}
    catch{throw new Error('Could not open backup: incorrect password or corrupted file');}finally{if(plain)plain.fill(0);}
  }
  function randomInt(n){const limit=Math.floor(256/n)*n,a=new Uint8Array(1);do{crypto.getRandomValues(a);}while(a[0]>=limit);return a[0]%n;}
  function generatePassword(n=20){insist(Number.isInteger(n)&&n>=12&&n<=128);const groups=['ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#$%&*+-=?'];const all=groups.join(''),a=groups.map(g=>g[randomInt(g.length)]);while(a.length<n)a.push(all[randomInt(all.length)]);for(let i=a.length-1;i>0;i--){let j=randomInt(i+1);[a[i],a[j]]=[a[j],a[i]];}return a.join('');}
  return {limits:PPS_LIMITS,validate,encryptBackup,decryptBackup,generatePassword,byteLength};
})();
if(typeof module!=='undefined')module.exports=PPS;
if(typeof document!=='undefined'){
  const $=id=>document.getElementById(id);
  let token='',records={schema:2,entries:[]},revision='',status={},editId='',editRevision='',networkRevision='',pendingImport=null,encryptedImport=null,importRevision='',restoreRevision='',busy=false,lastActivity=0,lastTouch=0;
  const revealTimers=new Set();
  function notice(message){$('notice').textContent=message;const dialog=document.querySelector('dialog[open]');if(dialog){let p=dialog.querySelector('.dialogNotice');if(!p){p=document.createElement('p');p.className='dialogNotice';p.setAttribute('role','status');dialog.prepend(p);}p.textContent=message;}}
  function authProgress(message,label){
    $('authProgress').hidden=!message;$('authProgressText').textContent=message;
    $('authForm').setAttribute('aria-busy',message?'true':'false');
    if(label)$('authSubmit').textContent=label;
  }
  async function run(fn){
    if(busy)return;busy=true;
    const states=[...document.querySelectorAll('button')].map(b=>[b,b.disabled]),authLabel=$('authSubmit').textContent;
    states.forEach(([b])=>b.disabled=true);
    try{notice('');await fn();}catch(e){notice(e.message||'Error');}
    finally{authProgress('');$('authSubmit').textContent=authLabel;states.forEach(([b,disabled])=>b.disabled=disabled);if(!token&&status.state)updateAuth();busy=false;}
  }
  async function api(path,data){
    const headers={};if(token)headers.Authorization='Bearer '+token;if(data!==undefined)headers['Content-Type']='application/json';
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),60000);let response,body;
    try{
      response=await fetch('/api/'+path,{method:data===undefined?'GET':'POST',headers,body:data===undefined?undefined:JSON.stringify(data),credentials:'omit',cache:'no-store',signal:controller.signal});
      try{body=await response.json();}catch(e){if(controller.signal.aborted)throw e;throw new Error('The device returned an incomplete response');}
    }catch(e){
      if(controller.signal.aborted)throw new Error('The device did not respond within 60 seconds. Check the connection. Before trying again, refresh the page and verify the result of the operation.');
      if(e instanceof TypeError)throw new Error('Could not connect to the device. Check Wi-Fi and access to the HTTPS page.');
      throw e;
    }finally{clearTimeout(timeout);}
    if(response.status===401&&token)clearClient();
    if(!response.ok){const errors={memory_unavailable:'Not enough RAM. Close unnecessary connections, refresh the list, and check the result before trying again.',invalid_request:'Invalid values. Check the fields and their limits.',invalid_credentials:'Incorrect current password.',storage_error:'Device storage error. Refresh the data before trying again.',vault_corrupt:'The vault is corrupted. Use recovery on the device.',no_previous_snapshot:'No valid previous snapshot is available. Import a backup.',unavailable:'This operation is currently unavailable. Check the device status.',serialization_error:'Could not prepare the complete device response.',setup_failed:'Setup or migration is incomplete. Check the status on the device.',session_expired:'Session ended. Log in again.'};if(body.error&&errors[body.error])throw new Error(errors[body.error]);if(response.status===409)throw new Error('The data has changed. Close the form, refresh the list, and try the change again.');if(response.status===429)throw new Error('Too many attempts. Wait and try again.');throw new Error(body.message||'Device error');}
    return {body,response};
  }
  function mask(){for(const timer of revealTimers)clearTimeout(timer);revealTimers.clear();document.querySelectorAll('.secret').forEach(el=>el.textContent='••••••••');}
  function clearClient(){mask();token='';records={schema:2,entries:[]};revision='';editId='';pendingImport=null;encryptedImport=null;$('records').replaceChildren();document.querySelectorAll('dialog').forEach(d=>d.close());document.querySelectorAll('form').forEach(f=>f.reset());$('extras').replaceChildren();$('vault').hidden=true;$('auth').hidden=false;status.state='locked';updateAuth();}
  function updateAuth(){const setup=['empty','legacy'].includes(status.state);$('codeLabel').hidden=!setup;$('confirmationLabel').hidden=status.state!=='empty';$('authTitle').textContent=setup?(status.state==='legacy'?'Migrate legacy vault':'Initial setup'):'Login';$('authSubmit').textContent=setup?'Confirm setup':'Log in';$('authHelp').textContent=setup?'Press SELECT on the device, set and confirm a new PIN. Enter the displayed code and your '+(status.state==='legacy'?'old master password.':'new master password (at least 12 bytes).'):['corrupt','fs_error'].includes(status.state)?'Vault error. Use physical recovery on the device; do not create a new vault over the old one.':'Enter your master password to access the records.';$('authSubmit').disabled=['corrupt','fs_error'].includes(status.state);$('connection').textContent='Device · '+(status.version||'PPS');}
  async function check(){status=(await api('status')).body;updateAuth();}
  async function refresh(){const r=await api('records');PPS.validate(r.body);records=r.body;revision=r.response.headers.get('X-Vault-Revision');if(!revision)throw new Error('Missing vault revision');render();}
  function element(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
  function action(text,fn,cls='secondary'){const b=element('button',text,cls);b.type='button';b.addEventListener('click',()=>run(fn));return b;}
  function render(){mask();$('records').replaceChildren();$('count').textContent=records.entries.length+' / '+PPS.limits.maxEntries+' · '+(PPS.byteLength(JSON.stringify(records))/1024).toFixed(1)+' / '+(PPS.limits.vaultBytes/1024)+' KiB';if(!records.entries.length)$('records').append(element('p','No records yet. Add your first record.'));
    for(const e of records.entries){const card=element('article');card.append(element('h3',e.site),element('p','Login: '+e.login));const secret=element('p','••••••••','secret');card.append(secret);for(const x of e.extras)card.append(element('p',x.name+': '+x.value));const actions=element('div',undefined,'actions');actions.append(action('Show for 10 seconds',()=>{mask();secret.textContent=e.password;const t=setTimeout(()=>{secret.textContent='••••••••';revealTimers.delete(t);},10000);revealTimers.add(t);}),action('Edit',()=>openEditor(e)),action('Delete',async()=>{if(!confirm('Delete record “'+e.site+'”?'))return;await api('delete',{id:e.id,revision});await refresh();},'danger'));card.append(actions);$('records').append(card);}
  }
  function addExtra(name='',value=''){if($('extras').children.length>=8)throw new Error('No more than 8 additional fields are allowed');const row=element('div',undefined,'extra'),n=element('input'),v=element('input');n.value=name;n.placeholder='Name';n.maxLength=64;n.required=true;n.setAttribute('aria-label','Field name');v.value=value;v.placeholder='Value';v.maxLength=512;v.setAttribute('aria-label','Field value');row.append(n,v,action('Delete',()=>row.remove()));$('extras').append(row);}
  function openEditor(e){if(!e&&records.entries.length>=PPS.limits.maxEntries)throw new Error('Limit reached: '+PPS.limits.maxEntries+' records');editId=e?.id||'';editRevision=revision;$('entryForm').reset();$('extras').replaceChildren();$('editorTitle').textContent=e?'Edit record':'New record';$('site').value=e?.site||'';$('login').value=e?.login||'';$('password').value=e?.password||'';for(const x of e?.extras||[])addExtra(x.name,x.value);$('editor').showModal();}
  function download(data,name){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'})),a=element('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function previewImport(data){const legacy=Array.isArray(data);PPS.validate(data,legacy);pendingImport={data,legacy};importRevision=revision;$('importSummary').textContent='Records in file: '+(legacy?data.length:data.entries.length)+'. Currently on device: '+records.entries.length+'.';$('importDialog').showModal();}
  document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>$(b.dataset.close).close()));
  document.querySelectorAll('dialog').forEach(d=>d.addEventListener('close',()=>{d.querySelectorAll('form').forEach(f=>f.reset());d.querySelectorAll('input').forEach(i=>{if(i.type!=='checkbox')i.value='';});const p=d.querySelector('.dialogNotice');if(p)p.remove();if(d.id==='editor'){$('extras').replaceChildren();editId='';}if(d.id==='importDialog')pendingImport=null;if(d.id==='decryptDialog')encryptedImport=null;}));
  $('checkStatus').onclick=()=>run(check);
  $('authForm').onsubmit=e=>{e.preventDefault();run(async()=>{
    const password=$('master').value,setup=['empty','legacy'].includes(status.state);
    if(status.state==='empty'&&(password!==$('masterConfirm').value||PPS.byteLength(password)<12))throw new Error('Passwords must match and be at least 12 bytes long');
    const code=$('setupCode').value.trim();$('master').value='';$('masterConfirm').value='';
    if(setup){
      authProgress(status.state==='legacy'?'Migrating records to the new vault… Do not close this page.':'Creating a secure vault… Do not close this page.','Setting up…');
      await api('setup',{password,code});authProgress('Checking device status…','Checking…');await check();
      notice('Setup complete. Log in with your master password.');return;
    }
    authProgress('Verifying master password… Do not close this page.','Logging in…');
    token=(await api('login',{password})).body.token;lastActivity=Date.now();lastTouch=0;
    authProgress('Loading records…','Loading…');await refresh();$('auth').hidden=true;$('vault').hidden=false;
  });};
  $('add').onclick=()=>run(()=>openEditor());$('refresh').onclick=()=>run(refresh);$('extraAdd').onclick=()=>run(()=>addExtra());$('generate').onclick=()=>run(()=>{$('password').value=PPS.generatePassword();notice('A new random password has been generated. Save the record.');});
  $('entryForm').onsubmit=e=>{e.preventDefault();run(async()=>{const entry={site:$('site').value,login:$('login').value,password:$('password').value,extras:[...$('extras').children].map(row=>({name:row.children[0].value,value:row.children[1].value}))};PPS.validate({schema:2,entries:[{...entry,id:editId||'0'.repeat(32)}]});if(editId)entry.id=editId;await api(editId?'edit':'add',editId?{revision:editRevision,id:editId,entry}:{revision:editRevision,entry});$('editor').close();await refresh();notice('Record saved');});};
  $('backup').onclick=()=>run(()=>{$('backupForm').reset();$('backupDialog').showModal();});
  $('backupForm').onsubmit=e=>{e.preventDefault();run(async()=>{if($('backupPassword').value!==$('backupConfirm').value)throw new Error('Backup passwords do not match');const p=$('backupPassword').value;$('backupForm').reset();const copy=await PPS.encryptBackup(records,p);download(copy,'pps-backup-encrypted.json');$('backupDialog').close();notice('Encrypted backup is ready');});};
  $('plainExport').onclick=()=>run(()=>{if(confirm('The file will contain all passwords in plain text. Download it?')){download(records,'pps-backup-UNENCRYPTED.json');$('backupDialog').close();}});
  $('importFile').onchange=()=>{const file=$('importFile').files[0];$('importFile').value='';if(!file)return;run(async()=>{if(file.size>131072)throw new Error('File exceeds 128 KiB');const data=JSON.parse(await file.text());if(data?.format==='pps-backup'){encryptedImport=data;$('decryptForm').reset();$('decryptDialog').showModal();}else previewImport(data);});};
  $('decryptForm').onsubmit=e=>{e.preventDefault();run(async()=>{const password=$('decryptPassword').value;$('decryptPassword').value='';const data=await PPS.decryptBackup(encryptedImport,password);$('decryptDialog').close();previewImport(data);});};
  $('confirmImport').onclick=()=>run(async()=>{if(!pendingImport)throw new Error('Select the file again');await api('import',{revision:importRevision,...pendingImport,confirm_replace:true});$('importDialog').close();await refresh();notice('Records replaced. The previous snapshot is available until the next write attempt. Save an external backup.');});
  $('restore').onclick=()=>run(()=>{restoreRevision=revision;$('restoreForm').reset();$('restoreDialog').showModal();});
  $('restoreForm').onsubmit=e=>{e.preventDefault();run(async()=>{const password=$('restorePassword').value;$('restorePassword').value='';await api('restore',{revision:restoreRevision,password,confirm_replace:true});clearClient();notice('Previous records restored. Your master password and PIN were preserved; log in again.');});};
  $('settings').onclick=()=>run(async()=>{const s=(await api('settings')).body;networkRevision=s.revision;$('networkForm').reset();$('ssid').value=s.ssid;$('apSsid').value=s.ap_ssid;$('wifiMode').value=s.wifi_mode;$('openWifi').checked=!s.has_password;$('networkWarning').textContent=s.warning||'';$('settingsDialog').showModal();});
  $('diagnostics').onclick=()=>run(async()=>{const d=(await api('diagnostics')).body;const kib=n=>Number.isFinite(n)?(n/1024).toFixed(1)+' KiB':'unavailable';$('diagnosticsResult').textContent=['Firmware: '+d.firmware,'Free RAM: '+kib(d.heap_free),'Minimum RAM since startup: '+kib(d.heap_min),'Largest free block: '+kib(d.heap_largest_block),'Allocation failures: '+d.allocation_failures,'Limit: '+d.max_entries+' records, '+kib(d.vault_max_bytes),'Arduino-ESP32: '+(d.arduino_core||'—')+'; ESP-IDF: '+(d.esp_idf||'—'),'ArduinoJson: '+d.arduinojson+'; Mbed TLS: '+d.mbedtls,d.tls_sdk_review_required?'TLS SDK security updates need to be reviewed; see the firmware release notes.':''].filter(Boolean).join('\n');});
  $('networkForm').onsubmit=e=>{e.preventDefault();run(async()=>{await api('settings',{revision:networkRevision,ssid:$('ssid').value,password:$('wifiPassword').value,ap_ssid:$('apSsid').value,ap_password:$('apPassword').value,wifi_mode:$('wifiMode').value,open_wifi:$('openWifi').checked});networkRevision=(await api('settings')).body.revision;$('wifiPassword').value='';$('apPassword').value='';notice('Settings saved. Click “Apply” to reconnect.');});};
  $('wifiPassword').addEventListener('input',()=>{if($('wifiPassword').value)$('openWifi').checked=false;});
  $('openWifi').addEventListener('change',()=>{if($('openWifi').checked)$('wifiPassword').value='';});
  $('applyNetwork').onclick=()=>run(async()=>{await api('apply',{});clearClient();notice('Connect to the selected network and open https://pps.local');});
  $('masterForm').onsubmit=e=>{e.preventDefault();run(async()=>{const old_password=$('oldMaster').value,new_password=$('newMaster').value;if(new_password!==$('newMasterConfirm').value||PPS.byteLength(new_password)<12||PPS.byteLength(new_password)>128)throw new Error('The new password must be 12–128 bytes long; both entries must match');$('masterForm').reset();await api('master',{old_password,new_password});clearClient();notice('Master password changed. All sessions are locked.');});};
  $('logout').onclick=()=>run(async()=>{try{await api('logout',{});}finally{clearClient();}});$('lock').onclick=()=>run(async()=>{try{await api('lock',{});}finally{clearClient();}});
  const activity=()=>{if(!token)return;lastActivity=Date.now();if(lastActivity-lastTouch>30000&&!busy){lastTouch=lastActivity;api('touch',{}).catch(()=>{});}};
  document.addEventListener('pointerdown',activity);document.addEventListener('keydown',activity);document.addEventListener('visibilitychange',()=>{if(document.hidden)mask();});
  setInterval(()=>{if(token&&Date.now()-lastActivity>=120000){const old=token;clearClient();fetch('/api/logout',{method:'POST',headers:{Authorization:'Bearer '+old,'Content-Type':'application/json'},body:'{}',credentials:'omit',keepalive:true}).catch(()=>{});notice('Session ended due to inactivity');}},10000);
  run(check);
}
