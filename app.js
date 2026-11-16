'use strict';
qrcode.stringToBytes=qrcode.stringToBytesFuncs['UTF-8'];
const $=id=>document.getElementById(id);let records=[],stream=null,timer=null,currentQr='',busy=false;
try{records=JSON.parse(localStorage.getItem('qr-studio-history')||'[]');if(!Array.isArray(records))records=[];records=records.filter(r=>r&&typeof r.text==='string'&&['read','generated'].includes(r.type)&&typeof r.date==='string')}catch{}
function assess(text){const reasons=[];let url;const s=text.trim();if(/^(javascript|data|vbscript|file):/i.test(s))return {url:null,reasons:['This code contains a potentially dangerous URL scheme.'],warning:true};try{url=new URL(/^www\./i.test(s)?'https://'+s:s)}catch{return {url:null,reasons,warning:false}}if(!['http:','https:'].includes(url.protocol))return {url:null,reasons,warning:false};if(url.protocol==='http:')reasons.push('This link uses unencrypted HTTP.');if(url.username||url.password)reasons.push('This URL hides credentials before the real destination.');if(/(^|\.)xn--/i.test(url.hostname))reasons.push('The domain uses encoded characters that can imitate another name.');if(/^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)||url.hostname.includes(':'))reasons.push('This link uses an IP address instead of a domain name.');if(['bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rb.gy'].includes(url.hostname))reasons.push('A shortened link conceals its final destination.');if(/\.(exe|scr|msi|bat|cmd|ps1|apk)(\/|$)/i.test(url.pathname))reasons.push('This link may download executable software.');if(url.hostname==='localhost'||url.hostname.endsWith('.local'))reasons.push('This link points to a local device.');return {url:url.href,reasons,warning:reasons.length>0}}
function save(type,text,source){const r={id:crypto.randomUUID(),type,text,source,date:new Date().toISOString()};records.unshift(r);try{localStorage.setItem('qr-studio-history',JSON.stringify(records))}catch{$('message').textContent='Your browser storage is full. This activity could not be saved.'}renderHistory();return r}
function node(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n}
let resultVersion = 0;
function showResult(text, record = records.find(r => r.text === text)) {
  const version = ++resultVersion;
  const a = assess(text), box = $('result');
  box.replaceChildren(); box.hidden = false;
  box.className = a.warning ? 'warning' : '';
  const heading = node('strong', '', a.warning ? '⚠ Suspicious link — take a closer look' : a.url ? '↗ Link found' : '✓ QR content');
  box.append(heading);
  let link, checking = false, unverified = true, flagged = a.warning;
  if (a.url) {
    link = node('a', a.warning ? 'red' : '', text);
    link.href = a.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
    link.addEventListener('click', event => {
      if (checking) { event.preventDefault(); return; }
      if ((flagged || unverified) && !confirm(flagged ? 'This link has warning signs. Opening it may be unsafe. Continue?' : 'This link is unverified. Continue at your own risk?')) event.preventDefault();
    });
    box.append(link);
  } else box.append(node('span', a.warning ? 'red' : '', text));
  for (const reason of a.reasons) box.append(node('p', 'red', reason));
  const copy = node('button', 'secondary', 'Copy content');
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(text); copy.textContent = 'Copied ✓'; }
    catch { $('message').textContent = 'Clipboard unavailable. Select the content to copy it.'; }
  };
  box.append(document.createElement('br'), copy);
  if (!a.url) return;
  const vt = node('div', 'vt-panel');
  box.append(vt);
  function saveCheck(data) {
    if (!record || !records.includes(record)) return;
    record.virustotal = { ...data, checked_at: new Date().toISOString() };
    try { localStorage.setItem('qr-studio-history', JSON.stringify(records)); } catch {}
    renderHistory();
  }
  async function runCheck(submit = false) {
    if (checking || version !== resultVersion) return;
    checking = true; unverified = true;
    link.setAttribute('aria-disabled', 'true');
    vt.replaceChildren(node('strong', '', submit ? 'Submitting URL to VirusTotal…' : 'Checking VirusTotal…'));
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    let data;
    try {
      const response = await fetch('/api/virustotal/check', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: a.url, submit }), signal: controller.signal
      });
      const body = await response.json();
      if (!response.ok) throw Error(body.message || 'VirusTotal check failed.');
      data = body;
    } catch (error) {
      data = { status: 'unavailable', message: error.name === 'AbortError' ? 'VirusTotal request timed out. Link safety is unverified.' : error.message.startsWith('Unexpected') ? 'Run python server.py to enable VirusTotal. Link safety is unverified.' : error.message };
    } finally { clearTimeout(timeout); checking = false; }
    saveCheck(data);
    if (version !== resultVersion) return;
    link.removeAttribute('aria-disabled');
    flagged = a.warning || data.status === 'flagged';
    unverified = data.status !== 'no_detections';
    link.classList.toggle('red', flagged);
    box.classList.toggle('warning', flagged);
    heading.textContent = flagged ? '⚠ Suspicious link — take a closer look' : '↗ Link found';
    const labels = {
      flagged: '⚠ VirusTotal: threats reported',
      no_detections: 'VirusTotal: no detections in the last report',
      stale: 'VirusTotal: report is older than 7 days — unverified',
      unknown: 'VirusTotal: incomplete report — unverified',
      not_found: 'VirusTotal: no report — unverified',
      queued: 'VirusTotal: analysis queued — unverified',
      unavailable: 'VirusTotal unavailable — unverified'
    };
    vt.replaceChildren(node('strong', flagged ? 'red' : '', labels[data.status] || 'VirusTotal: unverified'));
    if (data.stats) {
      vt.append(node('p', data.status === 'flagged' ? 'red' : '', `${data.stats.malicious} malicious · ${data.stats.suspicious} suspicious · ${data.stats.harmless} harmless · ${data.stats.undetected} undetected · ${data.stats.timeout} timed out`));
    }
    if (data.last_analysis) vt.append(node('p', '', 'Last analyzed: ' + new Date(data.last_analysis).toLocaleString()));
    vt.append(node('p', '', data.message || 'No report is available.'));
    vt.append(node('p', '', 'No detections does not mean a link is safe. New threats may be missed.'));
    const retry = node('button', 'secondary', 'Check report again');
    retry.onclick = () => runCheck(); vt.append(retry);
    if (data.status !== 'unavailable') {
      const scan = node('button', 'secondary', 'Submit for a new scan');
      scan.onclick = () => {
        if (confirm('Send the full URL to VirusTotal for analysis? Submitted URLs may be shared with its security community. Do not submit private, login, or password-reset links.')) runCheck(true);
      };
      vt.append(scan);
    }
    if (data.report_url && data.report_url.startsWith('https://www.virustotal.com/gui/url/')) {
      const reportLink = node('a', '', 'View VirusTotal report ↗');
      reportLink.href = data.report_url; reportLink.target = '_blank'; reportLink.rel = 'noopener noreferrer';
      vt.append(document.createElement('br'), reportLink);
    }
  }
  if ($('vtEnabled').checked) runCheck();
  else {
    vt.append(node('p', '', 'VirusTotal is off. Link safety is unverified.'));
    const check = node('button', 'secondary', 'Check with VirusTotal');
    check.onclick = () => runCheck(); vt.append(check);
  }
}
function renderHistory(){const list=$('historyList');list.replaceChildren();$('count').textContent=records.length;const visible=records.filter(r=>$('filter').value==='all'||r.type===$('filter').value);if(!visible.length){const empty=node('div','empty');empty.append(node('b','','◷'),node('span','',records.length?'No matching activity.':'Your next connection starts here. Scan or create a QR code.'));list.append(empty);return}for(const r of visible){const row=node('div','activity'),a=assess(r.text);if(r.virustotal?.status==='flagged')a.warning=true;row.append(node('span','activity-icon',r.type==='read'?'⌗':'＋'));const info=node('div','activity-main');info.append(node('strong',a.warning?'red':'',r.text),node('small','',new Date(r.date).toLocaleString()+' · '+r.source));if(r.virustotal)info.append(node('small',r.virustotal.status==='flagged'?'red':'','VirusTotal: '+r.virustotal.status.replaceAll('_',' ')));row.append(info,node('span','badge',r.type==='read'?'READ':'CREATED'));const view=node('button','','↗');view.setAttribute('aria-label','View activity');view.onclick=()=>{showResult(r.text,r);$('result').scrollIntoView({behavior:'smooth',block:'center'})};row.append(view);list.append(row)}}
function stopCamera(){clearTimeout(timer);if(stream)stream.getTracks().forEach(t=>t.stop());stream=null;$('video').srcObject=null;$('video').hidden=true;$('camera').textContent='◎  Scan with camera'}
function switchTab(generate){stopCamera();$('scanPanel').hidden=generate;$('generatePanel').hidden=!generate;$('scanTab').classList.toggle('active',!generate);$('generateTab').classList.toggle('active',generate);$('result').hidden=true;$('message').textContent=''}
$('scanTab').onclick=()=>switchTab(false);$('generateTab').onclick=()=>switchTab(true);
function loadScript(path){return new Promise((resolve,reject)=>{const s=document.createElement('script');s.src=path;s.onload=resolve;s.onerror=()=>reject(Error('Could not load image format decoder.'));document.head.append(s)})}let tiffReady,heicReady;
async function pixels(file){const ext=file.name.split('.').pop().toLowerCase();if(['tif','tiff'].includes(ext)||/tiff/.test(file.type)){await(tiffReady||=loadScript('https://cdn.jsdelivr.net/npm/pako@1.0.11/dist/pako.min.js').then(()=>loadScript('https://cdn.jsdelivr.net/npm/utif@3.1.0/UTIF.js')));const buffer=await file.arrayBuffer(),pages=UTIF.decode(buffer);if(!pages.length)throw Error('No image found in TIFF.');const page=pages[0];if(page.width*page.height>40000000)throw Error('Image is too large. Please resize it.');UTIF.decodeImage(buffer,page);return new ImageData(new Uint8ClampedArray(UTIF.toRGBA8(page)),page.width,page.height)}if(['heic','heif'].includes(ext)||/hei[cf]/.test(file.type)){await(heicReady||=loadScript('https://cdn.jsdelivr.net/npm/heic2any@0.0.4/dist/heic2any.min.js'));file=await heic2any({blob:file,toType:'image/png'});if(Array.isArray(file))file=file[0]}const url=URL.createObjectURL(file);try{const img=new Image();img.src=url;await img.decode();const scale=Math.min(1,2500/Math.max(img.naturalWidth,img.naturalHeight));const c=document.createElement('canvas');c.width=Math.max(1,Math.round(img.naturalWidth*scale));c.height=Math.max(1,Math.round(img.naturalHeight*scale));const ctx=c.getContext('2d',{willReadFrequently:true});ctx.fillStyle='#fff';ctx.fillRect(0,0,c.width,c.height);ctx.drawImage(img,0,0,c.width,c.height);return ctx.getImageData(0,0,c.width,c.height)}finally{URL.revokeObjectURL(url)}}
async function readFiles(files){if(busy)return;busy=true;stopCamera();for(const file of files){$('message').textContent='Reading '+file.name+'…';try{if(file.size>40*1024*1024)throw Error('Image exceeds the 40 MB limit.');const data=await pixels(file);const qr=jsQR(data.data,data.width,data.height,{inversionAttempts:'attemptBoth'});if(!qr)throw Error('No readable QR code found. Try a clear, closer image.');save('read',qr.data,file.name);showResult(qr.data);$('message').textContent='Read successfully · '+file.name}catch(e){$('message').textContent=file.name+': '+(e.message||'This format cannot be decoded. Try PNG or JPG.')}}busy=false;$('upload').value=''}
$('upload').onchange=e=>readFiles(e.target.files);$('drop').onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('upload').click()}};for(const type of ['dragenter','dragover'])$('drop').addEventListener(type,e=>{e.preventDefault();$('drop').classList.add('drag')});$('drop').ondragleave=()=>$('drop').classList.remove('drag');$('drop').ondrop=e=>{e.preventDefault();$('drop').classList.remove('drag');readFiles(e.dataTransfer.files)};
$('camera').onclick=async()=>{if(stream){stopCamera();return}try{stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'},audio:false});const v=$('video');v.hidden=false;v.srcObject=stream;await v.play();$('camera').textContent='Stop camera';$('message').textContent='Point the camera at a QR code.';const canvas=document.createElement('canvas'),ctx=canvas.getContext('2d',{willReadFrequently:true});const tick=()=>{if(!stream)return;if(v.readyState>=2){canvas.width=v.videoWidth;canvas.height=v.videoHeight;ctx.drawImage(v,0,0);const d=ctx.getImageData(0,0,canvas.width,canvas.height),qr=jsQR(d.data,d.width,d.height);if(qr){save('read',qr.data,'Camera');showResult(qr.data);$('message').textContent='Code read successfully.';stopCamera();return}}timer=setTimeout(tick,200)};tick()}catch{stopCamera();$('message').textContent='Camera unavailable or permission denied. Please upload an image instead.'}};
$('generate').onclick=()=>{const text=$('content').value.trim();if(!text){$('message').textContent='Enter a link or text first.';return}try{const qr=qrcode(0,$('quality').value);qr.addData(text,'Byte');qr.make();const canvas=document.createElement('canvas');const n=qr.getModuleCount(),unit=Math.max(4,Math.floor(900/(n+8)));canvas.width=canvas.height=(n+8)*unit;const ctx=canvas.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,canvas.width,canvas.height);const chosen=$('color').value;const rgb=chosen.match(/\w\w/g).map(v=>parseInt(v,16));if(rgb.reduce((a,b)=>a+b,0)>510)throw Error('Choose a darker color so your QR code stays readable.');ctx.fillStyle=chosen;for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(qr.isDark(y,x))ctx.fillRect((x+4)*unit,(y+4)*unit,unit,unit);currentQr=canvas.toDataURL('image/png');const img=node('img');img.src=currentQr;img.alt='Generated QR code';$('qrImage').replaceChildren(img);$('qrOutput').hidden=false;save('generated',text,'Generator');showResult(text);$('message').textContent='Your QR code is ready.'}catch(e){$('message').textContent=e.message||'Content is too long. Try shorter text.'}};
function download(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}$('download').onclick=()=>{const a=document.createElement('a');a.href=currentQr;a.download='qr-studio.png';a.click()};$('filter').onchange=renderHistory;$('clear').onclick=()=>{if(records.length&&confirm('Delete all activity saved in this browser?')){records=[];localStorage.removeItem('qr-studio-history');renderHistory()}};$('export').onclick=()=>download(new Blob([JSON.stringify(records,null,2)],{type:'application/json'}),'qr-studio-history.json');window.addEventListener('pagehide',stopCamera);renderHistory();
