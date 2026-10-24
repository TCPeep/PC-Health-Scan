# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Repair Console web page (served by RepairConsole.ps1). ASCII-only source.

function Get-RepairPageHtml {
    param([string]$Token, $Items, $Meta, [timespan]$ScanAge, [switch]$ForcedDryRun, [string]$Store, [string]$SessionId)
    $sb = New-Object System.Text.StringBuilder
    $css = $script:ReportCss
    if (-not $css) { . (Join-Path $PSScriptRoot 'Report.ps1'); $css = $script:ReportCss }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    [void]$sb.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Repair Console - " + (& $enc $Meta.Computer) + "</title><style>$css</style><style>" + @'
.item{background:var(--panel);border:1px solid var(--border);border-left:5px solid var(--info);border-radius:10px;padding:12px 16px;margin:10px 0}
.item.sev-critical{border-left-color:var(--critical)}.item.sev-high{border-left-color:var(--high)}.item.sev-medium{border-left-color:var(--medium)}.item.sev-low{border-left-color:var(--low)}
.item.ok{border-left-color:var(--good)}.item.fail{outline:2px solid var(--high)}.item.undone{opacity:.75}
.steps{margin:8px 0;padding:0;list-style:none}.steps li{display:flex;gap:8px;align-items:flex-start;padding:3px 0;font-size:14px}
.steps input{margin-top:4px}.risk{font-size:11px;padding:1px 7px;border-radius:999px;white-space:nowrap}
.risk.safe{background:var(--good-bg);color:var(--good)}.risk.caution{background:var(--medium-bg);color:var(--medium)}.risk.guided{background:var(--low-bg);color:var(--low)}
.offnote{font-size:12px;color:var(--muted);margin:2px 0 0}
.ibtns{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;align-items:center}
.ibtns button,.ubtn{font:inherit;font-size:13.5px;padding:6px 12px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer}
.ibtns button.apply{background:var(--accent);border-color:var(--accent);color:#fff}.ibtns button.undo{border-color:var(--medium);color:var(--medium)}
.ibtns button:disabled,.ubtn:disabled{opacity:.5;cursor:default}
.status{font-size:13px;color:var(--muted)}.status.ok{color:var(--good)}.status.fail{color:var(--high)}.status.run{color:var(--accent)}
pre.log{display:none;background:#0d1117;color:#d7dde6;border-radius:8px;padding:10px 12px;margin:8px 0 0;font:12.5px/1.5 Consolas,"Cascadia Mono",monospace;max-height:340px;overflow:auto;white-space:pre-wrap;word-break:break-all}
pre.log.show{display:block}pre.log .sim{color:#9fb3c8}pre.log .bad{color:#ff8a8a}pre.log .hd{color:#7ee787;font-weight:600}pre.log .un{color:#f0c34e;font-weight:600}
.banner{background:var(--medium-bg);border:1px solid var(--border);border-radius:10px;padding:10px 14px;margin:14px 0}
.banner.sim{background:var(--low-bg)}
.topbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:14px 0}
.topbar button{font:inherit;font-size:14px;padding:7px 14px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer}
.topbar button.undoall{border-color:var(--medium);color:var(--medium)}
.topbar label{font-size:14px;display:flex;gap:6px;align-items:center}
.sumline{font-size:14px;color:var(--muted)}
#undo-panel{display:none;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin:10px 0}
#undo-panel.show{display:block}
#undo-panel table{width:100%;border-collapse:collapse;font-size:13.5px}#undo-panel td,#undo-panel th{padding:6px 8px;border-top:1px solid var(--border);text-align:left;vertical-align:top}
#undo-panel tr.done td{opacity:.55}#undo-panel .sess{font-weight:600;padding-top:14px;border-top:none}
.muted{color:var(--muted)}
'@ + '</style></head><body>')
    [void]$sb.Append("<header class='top'><div class='wrap'><div class='brand'>PC Health Scan</div><h1>Repair Console - " + (& $enc $Meta.Computer) + "</h1><div class='meta'>" + (& $enc $Meta.OSLine) + " &middot; scan from " + (& $enc ([datetime]$Meta.Started).ToString('yyyy-MM-dd HH:mm')) + " (" + [int]$ScanAge.TotalMinutes + " min ago) &middot; $($Items.Count) repairable issue(s)</div></div></header><main class='wrap'>")
    if ($ScanAge.TotalHours -gt 12) { [void]$sb.Append("<div class='banner'>This scan is " + [int]$ScanAge.TotalHours + " hours old. Things may have changed since - consider re-running START-SCAN.cmd first.</div>") }
    if ($ForcedDryRun) { [void]$sb.Append("<div class='banner sim'><b>Forced SIMULATE mode:</b> nothing will be changed no matter which button you press (Undo included).</div>") }
    [void]$sb.Append(@"
<div class='banner sim'><b>How this works.</b> <b>Simulate</b> shows exactly what a fix would do without changing anything. <b>Apply</b> does it with a live log.
Repairs run <b>one at a time</b>; clicking several just queues them. <b>Every change can be undone</b>: an applied fix gets an <b>Undo this fix</b> button,
and <b>Undo &amp; restore</b> (top) lists every change ever made on this PC - including earlier sessions - with its own Undo button.
Removed files go to a protected quarantine instead of being deleted, settings and registry keys are backed up first, and one System Restore point is made per session as a last resort.
Steps marked <span class='risk caution'>caution</span> remove or disable something. Steps that start <b>unticked</b> are ones where the item may well be legitimate - only tick them if you know it is unwanted.
<span class='risk guided'>guided</span> steps only open the right settings page.</div>
<div class='topbar'><button id='undo-toggle' class='undoall'>Undo &amp; restore...</button><button id='rstrui'>Open System Restore</button><button id='sim-all'>Simulate everything</button><button id='apply-safe'>Apply all ticked "safe" steps</button><label><input type='checkbox' id='autoscroll' checked> Auto-scroll logs</label><span class='sumline' id='sum'></span><button id='finish' style='margin-left:auto'>Finish &amp; close console</button></div>
<section id='undo-panel'><div style='display:flex;gap:10px;align-items:center;flex-wrap:wrap'><h2 style='margin:4px 0'>Undo &amp; restore</h2><button class='ubtn' id='undo-session'>Undo everything from this session</button><button class='ubtn' id='undo-refresh'>Refresh</button><span class='muted' id='undo-store'></span></div>
<p class='muted'>Newest first. Undoing a change puts back exactly what was there before it (registry values, tasks, services, files from quarantine, firewall rules, DNS, Defender settings...). Uninstalls and deleted temp files cannot be reversed here - use <b>Open System Restore</b> for those.</p>
<div id='undo-list'>Loading...</div><pre class='log' id='log-undo'></pre></section>
"@)
    foreach ($it in $Items) {
        $cls = switch ($it.Severity) { 'Critical' { 'critical' } 'High' { 'high' } 'Medium' { 'medium' } 'Low' { 'low' } default { '' } }
        [void]$sb.Append("<article class='item sev-$cls' id='$($it.Id)' data-id='$($it.Id)'><div class='fhead'><span class='pill $cls'>$($it.Severity)</span><span class='cat'>" + (& $enc $it.Category) + "</span><span class='status' id='st-$($it.Id)'></span></div>")
        [void]$sb.Append('<h3>' + (& $enc $it.Title) + '</h3>')
        if ($it.Detail) { [void]$sb.Append("<p class='detail'>" + (& $enc $it.Detail) + '</p>') }
        [void]$sb.Append("<ul class='steps'>")
        $i = 0; $anyOff = $false
        foreach ($s in $it.Steps) {
            $risk = [string]$s['Risk']; if (-not $risk) { $risk = 'safe' }
            $off = ([string]$s['Off'] -eq 'True')
            if ($off) { $anyOff = $true }
            $rb = if ([string]$s['Reboot'] -eq 'True') { " <span class='risk guided'>restart needed</span>" } else { '' }
            [void]$sb.Append("<li><input type='checkbox' data-step='$i'" + $(if ($off) { ' data-off' } else { ' checked' }) + "> <span class='risk $risk'>$risk</span><span>" + (& $enc $s['Label']) + "$rb</span></li>")
            $i++
        }
        [void]$sb.Append('</ul>')
        if ($anyOff) { [void]$sb.Append("<p class='offnote'>Nothing is ticked here on purpose: this is unsigned rather than known adware. Look at it first - if it is a program you know (your own software, a game tool...), tick &ldquo;trust it&rdquo; instead.</p>") }
        [void]$sb.Append("<div class='ibtns'><button class='sim'>Simulate</button><button class='apply'>Apply selected</button><button class='undo' style='display:none'>Undo this fix</button><button class='showlog'>Show log</button></div><pre class='log' id='log-$($it.Id)'></pre></article>")
    }
    if ($Items.Count -eq 0) { [void]$sb.Append("<p class='empty'>No repairable issues in this scan. You can still undo earlier changes with <b>Undo &amp; restore</b>.</p>") }
    [void]$sb.Append("<footer><p class='muted'>PC Health Scan by TCPeep (github.com/TCPeep/PC-Health-Scan, free software under GPL-3.0)</p></footer>")
    [void]$sb.Append("</main><script>var TOKEN=" + (ConvertTo-Json ([string]$Token)) + ";var FORCED=" + $(if ($ForcedDryRun) { 'true' } else { 'false' }) + ";" + @'
(function(){
var H={'X-Repair':'1'};
function api(path,opts){opts=opts||{};var u=path+(path.indexOf('?')>=0?'&':'?')+'t='+encodeURIComponent(TOKEN);return fetch(u,{method:opts.method||'GET',headers:H}).then(function(r){return r.json()})}
var busy={},lastJob={},totals={ok:0,fail:0};
function esc(s){return String(s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
function fmt(line){var c='';if(line.indexOf('[SIMULATE]')>=0)c='sim';if(/FAILED|REFUSED|could not|NOT restored|refused/i.test(line))c='bad';if(line.indexOf('UNDO')>=0)c='un';else if(line.indexOf('####')>=0||line.indexOf('== ')>=0)c='hd';return c?'<span class="'+c+'">'+esc(line)+'</span>':esc(line)}
function sumline(){document.getElementById('sum').textContent='Applied OK: '+totals.ok+(totals.fail?'  Failed: '+totals.fail:'')}
/* follow a queued/running job's log until it finishes */
function follow(job,log,st,label){var since=0;return new Promise(function(res){(function poll(){api('/api/log?job='+job+'&since='+since).then(function(l){
  if(l.lines&&l.lines.length){log.innerHTML+=l.lines.map(fmt).join('\n')+'\n';if(document.getElementById('autoscroll').checked)log.scrollTop=log.scrollHeight;since=l.next}
  if(!l.done){if(st){if(l.status==='queued'){st.textContent='Queued (#'+l.position+') - waiting for the repair before it';st.className='status'}else{st.textContent=label+'...';st.className='status run'}}setTimeout(poll,500)}else res(l)
 }).catch(function(){setTimeout(poll,1500)})})()})}
function lockCard(card,on){card.querySelectorAll('button').forEach(function(b){if(!b.classList.contains('showlog'))b.disabled=on})}
function run(card,mode){var id=card.getAttribute('data-id');if(busy[id])return Promise.resolve();
 var steps=[].slice.call(card.querySelectorAll('input[data-step]')).filter(function(c){return c.checked}).map(function(c){return c.getAttribute('data-step')});
 if(!steps.length){if(!run.quiet)alert('Tick at least one step.');return Promise.resolve()}
 if(mode==='apply'&&!run.quiet){var caution=[].slice.call(card.querySelectorAll('input[data-step]:checked')).some(function(c){return c.parentNode.querySelector('.risk.caution')});
  if(!confirm((caution?'This will remove or disable something on this PC.\nIt can be reversed afterwards with "Undo this fix".\n\n':'')+'Apply '+steps.length+' step(s) for:\n'+card.querySelector('h3').textContent+' ?'))return Promise.resolve()}
 busy[id]=true;var st=document.getElementById('st-'+id),log=document.getElementById('log-'+id);log.classList.add('show');lockCard(card,true);
 return api('/api/run?id='+id+'&mode='+mode+'&steps='+steps.join(','),{method:'POST'}).then(function(r){
  if(!r.job){st.textContent='Error: '+(r.error||'?');st.className='status fail';busy[id]=false;lockCard(card,false);return}
  return follow(r.job,log,st,mode==='apply'?'Applying':'Simulating').then(function(l){busy[id]=false;lockCard(card,false);
   if(mode==='apply'&&!FORCED){if(l.ok){st.textContent='Applied'+(l.reboot?' - restart needed':'');st.className='status ok';card.classList.add('ok');card.classList.remove('fail','undone');totals.ok++}
     else{st.textContent='Finished with errors - see log';st.className='status fail';card.classList.add('fail');totals.fail++}
     if(l.changes>0){lastJob[id]=r.job;var u=card.querySelector('.undo');u.style.display='';u.textContent='Undo this fix ('+l.changes+' change'+(l.changes==1?'':'s')+')'}}
   else{st.textContent='Simulated - nothing changed';st.className='status'}
   sumline();if(document.getElementById('undo-panel').classList.contains('show'))loadUndo()})})}
function undoJob(card){var id=card.getAttribute('data-id'),job=lastJob[id];if(!job||busy[id])return;
 if(!confirm('Put back everything this fix changed?\n\n'+card.querySelector('h3').textContent))return;
 busy[id]=true;lockCard(card,true);var st=document.getElementById('st-'+id),log=document.getElementById('log-'+id);log.classList.add('show');
 api('/api/undo?job='+job+'&item='+id,{method:'POST'}).then(function(r){if(!r.job){alert(r.error||'Nothing to undo');busy[id]=false;lockCard(card,false);return}
  follow(r.job,log,st,'Undoing').then(function(l){busy[id]=false;lockCard(card,false);
   st.textContent=l.ok?'Undone - back to how it was':'Undo finished with errors - see log';st.className='status '+(l.ok?'':'fail');
   if(l.ok){card.classList.remove('ok');card.classList.add('undone');card.querySelector('.undo').style.display='none';delete lastJob[id]}
   if(document.getElementById('undo-panel').classList.contains('show'))loadUndo()})})}
document.querySelectorAll('.item').forEach(function(card){
 card.querySelector('.sim').addEventListener('click',function(){run(card,'simulate')});
 card.querySelector('.apply').addEventListener('click',function(){run(card,'apply')});
 card.querySelector('.undo').addEventListener('click',function(){undoJob(card)});
 card.querySelector('.showlog').addEventListener('click',function(){document.getElementById('log-'+card.getAttribute('data-id')).classList.toggle('show')})});
function seq(cards,mode,safeOnly){var p=Promise.resolve();cards.forEach(function(card){p=p.then(function(){
  if(safeOnly){card.querySelectorAll('input[data-step]').forEach(function(c){c.checked=!!c.parentNode.querySelector('.risk.safe')&&!c.hasAttribute('data-off')});if(!card.querySelector('input[data-step]:checked'))return}
  return run(card,mode)})});return p}
document.getElementById('sim-all').addEventListener('click',function(){run.quiet=true;seq([].slice.call(document.querySelectorAll('.item')),'simulate',false).then(function(){run.quiet=false})});
document.getElementById('apply-safe').addEventListener('click',function(){if(!confirm('Apply every step marked "safe" (settings-only, all undoable) on all issues?\nSteps that start unticked are skipped.'))return;
 run.quiet=true;seq([].slice.call(document.querySelectorAll('.item')),'apply',true).then(function(){run.quiet=false})});
/* ---- undo panel */
var panel=document.getElementById('undo-panel');
function loadUndo(){api('/api/undo/list').then(function(d){var recs=(d.records||[]).slice().sort(function(a,b){return a.time<b.time?1:-1});
 document.getElementById('undo-store').textContent=d.store?('Stored in '+d.store):'';
 var open=recs.filter(function(r){return !r.undone&&r.undoable}).length;document.getElementById('undo-toggle').textContent='Undo & restore ('+open+')...';
 if(!recs.length){document.getElementById('undo-list').innerHTML='<p class="muted">No changes have been made on this PC yet.</p>';return}
 var h='<table><tr><th>When</th><th>Change</th><th>From fix</th><th></th></tr>',sess=null;
 recs.forEach(function(r){if(r.session!==sess){sess=r.session;h+='<tr><td colspan="4" class="sess">'+(r.current?'This session':'Session '+esc(r.session))+'</td></tr>'}
  var act=r.undone?'<span class="muted">undone</span>':(r.undoable?'<button class="ubtn" data-rec="'+esc(r.id)+'">'+(r.legacy?'Restore':'Undo')+'</button>':'<span class="muted" title="'+esc(r.reason)+'">not undoable here</span>');
  h+='<tr class="'+(r.undone?'done':'')+'"><td>'+esc(r.time.replace('T',' '))+'</td><td>'+esc(r.desc)+(r.undoable||r.undone?'':'<br><span class="muted">'+esc(r.reason)+'</span>')+'</td><td>'+esc(r.item)+'</td><td>'+act+'</td></tr>'});
 document.getElementById('undo-list').innerHTML=h+'</table>';
 document.querySelectorAll('#undo-list button[data-rec]').forEach(function(b){b.addEventListener('click',function(){undoRec(b.getAttribute('data-rec'),b)})})})}
function undoRec(rec,btn){if(!confirm('Undo this change?'))return;btn.disabled=true;var log=document.getElementById('log-undo');log.classList.add('show');
 api('/api/undo?rec='+encodeURIComponent(rec),{method:'POST'}).then(function(r){if(!r.job){alert(r.error||'Nothing to undo');btn.disabled=false;return}
  follow(r.job,log,null,'').then(function(){loadUndo()})})}
document.getElementById('undo-toggle').addEventListener('click',function(){panel.classList.toggle('show');if(panel.classList.contains('show'))loadUndo()});
document.getElementById('undo-refresh').addEventListener('click',loadUndo);
document.getElementById('undo-session').addEventListener('click',function(){if(!confirm('Undo EVERY change made in this session, newest first?'))return;var log=document.getElementById('log-undo');log.classList.add('show');
 api('/api/undo?scope=session',{method:'POST'}).then(function(r){if(!r.job){alert(r.error||'Nothing to undo');return}follow(r.job,log,null,'').then(function(){loadUndo();
  document.querySelectorAll('.item.ok').forEach(function(c){c.classList.remove('ok');c.classList.add('undone');c.querySelector('.undo').style.display='none'})})})});
document.getElementById('rstrui').addEventListener('click',function(){if(confirm('Open Windows System Restore?\n(Choosing a restore point undoes ALL changes since then, including ones not made by this tool, and restarts the PC.)'))api('/api/open?what=rstrui',{method:'POST'})});
document.getElementById('finish').addEventListener('click',function(){if(!confirm('Close the Repair Console?\nYou can reopen it any time with RUN-REPAIRS.cmd - the Undo history stays.'))return;
 api('/api/finish',{method:'POST'}).then(function(r){if(r.busy){if(!confirm('"'+r.title+'" is still running. Close anyway? (A running DISM/SFC keeps going in the background.)'))return;return api('/api/finish?force=1',{method:'POST'})}return r}).then(function(r){if(r&&r.ok)document.body.innerHTML='<main class="wrap"><h2>Repair Console closed.</h2><p>Re-run START-SCAN.cmd to verify the fixes. To undo anything later, open RUN-REPAIRS.cmd again and use Undo &amp; restore.</p></main>'})});
loadUndo();
})();
'@ + '</script></body></html>')
    $sb.ToString()
}
