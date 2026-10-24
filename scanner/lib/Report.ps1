# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# PC Health Scan - HTML report renderer (ASCII-only source)

$script:SecurityCategories = @('Malware & PUPs', 'Persistence', 'Browser', 'Security Settings', 'Antivirus', 'Updates', 'Accounts & Access', 'Network', 'Software')
$script:HealthCategories = @('Hardware', 'Storage', 'Stability', 'Performance', 'System Integrity', 'Drivers')

function HE {
    param($Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-ScoreInfo {
    param([string[]]$Categories)
    $crit = 0; $high = 0; $med = 0; $low = 0
    foreach ($f in $script:Findings) {
        if ($Categories -notcontains $f.Category) { continue }
        switch ($f.Severity) { 'Critical' { $crit++ } 'High' { $high++ } 'Medium' { $med++ } 'Low' { $low++ } }
    }
    $pen = ($crit * 30) + ($high * 12) + [Math]::Min(30, $med * 5) + [Math]::Min(10, $low)
    $score = [Math]::Max(0, 100 - $pen)
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 75) { 'B' } elseif ($score -ge 60) { 'C' } elseif ($score -ge 40) { 'D' } else { 'F' }
    $tone = if ($score -ge 90) { 'good' } elseif ($score -ge 75) { 'low' } elseif ($score -ge 60) { 'medium' } elseif ($score -ge 40) { 'high' } else { 'critical' }
    [pscustomobject]@{ Score = $score; Grade = $grade; Tone = $tone }
}

function ConvertTo-CellHtml {
    param($Value, [string]$Column)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return (HE $Value.ToString('yyyy-MM-dd HH:mm')) }
    if ($Value -is [bool]) { if ($Value) { return 'Yes' } else { return 'No' } }
    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $Value = (@($Value | ForEach-Object { [string]$_ }) -join '; ')
    }
    $s = [string]$Value
    if ($Column -eq 'SHA256' -and $s -match '^[A-Fa-f0-9]{64}$') {
        return ("<a class='hash' href='https://www.virustotal.com/gui/file/{0}' target='_blank' rel='noopener noreferrer' title='Look up on VirusTotal (search only, nothing is uploaded)'>{1}&hellip;</a>" -f $s, $s.Substring(0, 12))
    }
    if ($s.Length -gt 1500) { $s = $s.Substring(0, 1500) + ' ...' }
    HE $s
}

function Get-BlockHtml {
    param($Block, [string]$TableId)
    $sb = New-Object System.Text.StringBuilder
    if ($Block.Kind -eq 'note') {
        [void]$sb.Append("<p class='note tone-$($Block.Tone)'>" + (HE $Block.Text) + '</p>')
        return $sb.ToString()
    }
    $rows = @($Block.Rows)
    $title = HE $Block.Title
    if ($Block.Kind -eq 'table') { $title += " <span class='count'>" + $rows.Count + '</span>' }
    if ($Block.Title) { [void]$sb.Append("<h3>$title</h3>") }
    if ($Block.Note) { [void]$sb.Append("<p class='bnote'>" + (HE $Block.Note) + '</p>') }
    if ($rows.Count -eq 0) {
        [void]$sb.Append("<p class='empty'>" + (HE $Block.Empty) + '</p>')
        return $sb.ToString()
    }
    $cols = @($Block.Columns)
    if ($Block.Kind -eq 'table' -and $rows.Count -gt 8) {
        [void]$sb.Append("<input class='tfilter' type='search' placeholder='Filter these rows...' data-target='$TableId'>")
    }
    $cls = if ($Block.Kind -eq 'kv') { 'data kv' } else { 'data' }
    [void]$sb.Append("<div class='tw'><table id='$TableId' class='$cls'><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append('<th>' + (HE $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    $n = 0
    foreach ($r in $rows) {
        $n++
        if ($n -gt 3000) { break }
        $flag = $r._Flag
        if ($flag) { [void]$sb.Append("<tr class='f-$flag'>") } else { [void]$sb.Append('<tr>') }
        foreach ($c in $cols) { [void]$sb.Append('<td>' + (ConvertTo-CellHtml $r.$c $c) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($rows.Count -gt 3000) { [void]$sb.Append("<p class='bnote'>Showing the first 3000 of $($rows.Count) rows. Full data is in findings.json.</p>") }
    $sb.ToString()
}

function Get-FindingHtml {
    param($F)
    $sev = $F.Severity
    $cls = ConvertTo-FlagClass $sev
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<article class='finding sev-$cls' data-sev='$sev' id='$($F.Id)'>")
    [void]$sb.Append("<div class='fhead'><span class='pill $cls'>$sev</span><span class='cat'>" + (HE $F.Category) + '</span>')
    $nAct = @($F.Actions).Count
    if ($nAct -gt 0) { [void]$sb.Append("<span class='pill good' title='RUN-REPAIRS.cmd offers a one-click fix for this'>Repairable ($nAct step$(if ($nAct -ne 1) { 's' }))</span>") }
    if ($sev -ne 'Info') { [void]$sb.Append("<label class='done'><input type='checkbox' data-fid='$($F.Id)'> Fixed</label>") }
    [void]$sb.Append('</div>')
    [void]$sb.Append('<h3>' + (HE $F.Title) + '</h3>')
    if ($F.Detail) { [void]$sb.Append("<p class='detail'>" + ((HE $F.Detail) -replace "`n", '<br>') + '</p>') }
    if ($F.Why) { [void]$sb.Append("<p class='why'><b>Why it matters:</b> " + ((HE $F.Why) -replace "`n", '<br>') + '</p>') }
    if ($F.Fix) { [void]$sb.Append("<p class='fix'><b>What to do:</b> " + ((HE $F.Fix) -replace "`n", '<br>') + '</p>') }
    $ev = @($F.Evidence)
    if ($ev.Count -gt 0) {
        $open = if ($ev.Count -le 3) { ' open' } else { '' }
        [void]$sb.Append("<details class='ev'$open><summary>Evidence ($($ev.Count))</summary><ul>")
        foreach ($e in $ev) { [void]$sb.Append('<li><code>' + (HE $e) + '</code></li>') }
        [void]$sb.Append('</ul></details>')
    }
    if ($F.Section) { [void]$sb.Append("<a class='more' href='#sec-$($F.Section)'>Open the $(HE (Get-SectionObj $F.Section).Title) section</a>") }
    [void]$sb.Append('</article>')
    $sb.ToString()
}

function New-HtmlReport {
    param([string]$Path, $Meta)
    $sec = Get-ScoreInfo $script:SecurityCategories
    $hea = Get-ScoreInfo $script:HealthCategories
    $sorted = @($script:Findings | Sort-Object @{ Expression = 'Rank'; Descending = $true }, Category, Title)
    $actionable = @($sorted | Where-Object { $_.Severity -ne 'Info' })
    $infos = @($sorted | Where-Object { $_.Severity -eq 'Info' })
    $cnt = @{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $cnt[$s] = @($sorted | Where-Object { $_.Severity -eq $s }).Count }

    $top = @($actionable | Where-Object { $_.Rank -ge 4 } | Select-Object -First 4 | ForEach-Object { $_.Title })
    if (($cnt['Critical'] + $cnt['High']) -eq 0) {
        $exec = 'No critical or high-priority problems were found.'
        if ($cnt['Medium'] -gt 0) { $exec += " There are $($cnt['Medium']) medium-priority items worth tidying up." }
    } else {
        $parts = @()
        if ($cnt['Critical'] -gt 0) { $parts += "$($cnt['Critical']) critical" }
        if ($cnt['High'] -gt 0) { $parts += "$($cnt['High']) high-priority" }
        $exec = "Found $($parts -join ' and ') issue(s) that should be dealt with. Most important: " + ($top -join '; ') + '.'
    }

    $sb = New-Object System.Text.StringBuilder
    $rid = 'pchs-' + $Meta.Computer + '-' + $Meta.Started.ToString('yyyyMMddHHmm')
    $fileName = [IO.Path]::GetFileName($Path)
    [void]$sb.Append("<!DOCTYPE html>`n<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>")
    [void]$sb.Append('<title>PC Health Report - ' + (HE $Meta.Computer) + '</title><style>' + $script:ReportCss + '</style></head>')
    [void]$sb.Append("<body data-rid='" + (HE $rid) + "' data-file='" + (HE $fileName) + "'>")

    # header
    [void]$sb.Append("<header class='top'><div class='wrap'><div class='brand'>PC Health &amp; Security Report</div>")
    [void]$sb.Append('<h1>' + (HE $Meta.Computer) + '</h1>')
    [void]$sb.Append("<div class='meta'>" + (HE $Meta.OSLine) + ' &middot; scanned ' + (HE $Meta.Started.ToString('yyyy-MM-dd HH:mm')) + ' as ' + (HE $Meta.User) + ' &middot; ' + (HE $Meta.Mode) + ' scan, ' + (HE $Meta.Duration))
    if (-not $Meta.Admin) { [void]$sb.Append(" &middot; <b class='warn'>not run as administrator (some checks skipped)</b>") }
    [void]$sb.Append('</div></div></header><main class=''wrap''>')

    # summary
    [void]$sb.Append("<section class='summary'>")
    foreach ($pair in @(@('Security', $sec), @('Health', $hea))) {
        $s = $pair[1]
        [void]$sb.Append("<div class='card score tone-$($s.Tone)'><div class='lbl'>$($pair[0])</div><div class='grade'>$($s.Grade)</div><div class='num'>$($s.Score) / 100</div></div>")
    }
    [void]$sb.Append("<div class='card counts'>")
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') {
        $c = ConvertTo-FlagClass $s
        [void]$sb.Append("<div class='cnt'><span class='pill $c'>$s</span><b>$($cnt[$s])</b></div>")
    }
    [void]$sb.Append("<div class='cnt'><span class='pill good'>Passed</span><b>$($script:Passes.Count)</b></div></div></section>")
    [void]$sb.Append("<p class='exec'>" + (HE $exec) + '</p>')

    # toc
    [void]$sb.Append("<nav class='toc'><a href='#findings'>Issues</a><a href='#passed'>Looks good</a><a href='#notes'>Notes &amp; actions</a>")
    foreach ($x in $script:Sections) { [void]$sb.Append("<a href='#sec-$($x.Id)'>" + (HE $x.Title) + '</a>') }
    [void]$sb.Append('</nav>')

    # findings
    [void]$sb.Append("<section id='findings'><div class='shead'><h2>What needs attention</h2><div class='chips'>")
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { [void]$sb.Append("<button class='chip' data-sev='$s'>$s ($($cnt[$s]))</button>") }
    [void]$sb.Append('</div></div>')
    if ($actionable.Count -eq 0) { [void]$sb.Append("<p class='empty'>Nothing to fix. Nice.</p>") }
    foreach ($f in $actionable) { [void]$sb.Append((Get-FindingHtml $f)) }
    if ($infos.Count -gt 0) {
        [void]$sb.Append("<details class='infos'><summary>Informational notes ($($infos.Count))</summary>")
        foreach ($f in $infos) { [void]$sb.Append((Get-FindingHtml $f)) }
        [void]$sb.Append('</details>')
    }
    [void]$sb.Append('</section>')

    # passes
    [void]$sb.Append("<section id='passed'><h2>What looks good</h2><ul class='passes'>")
    foreach ($p in ($script:Passes | Sort-Object Category, Title)) {
        $d = if ($p.Detail) { " <span class='muted'>- " + (HE $p.Detail) + '</span>' } else { '' }
        [void]$sb.Append("<li><span class='ok'>&#10003;</span> <b>" + (HE $p.Title) + '</b>' + $d + " <span class='cat'>" + (HE $p.Category) + '</span></li>')
    }
    [void]$sb.Append('</ul></section>')

    # notes & actions
    [void]$sb.Append("<section id='notes'><h2>Technician notes &amp; actions taken</h2>")
    [void]$sb.Append("<p class='bnote'>Issues marked <span class='pill good'>Repairable</span> can be fixed with one click (with a live log) by running <b>RUN-REPAIRS.cmd</b> from the scan folder. Tick &ldquo;Fixed&rdquo; on issues as you resolve them and write down what you changed. Notes autosave in this browser; press <b>Save report</b> to download a copy with the notes and ticks baked in.</p>")
    if ($script:Actions.Count -gt 0) {
        [void]$sb.Append('<h3>Actions performed by the scanner</h3><ul class=''actions''>')
        foreach ($a in $script:Actions) { [void]$sb.Append('<li><span class=''muted''>' + $a.Time.ToString('HH:mm:ss') + '</span> ' + (HE $a.Action) + '</li>') }
        [void]$sb.Append('</ul>')
    } else {
        [void]$sb.Append("<p class='muted'>The scanner made no changes to this PC (read-only scan).</p>")
    }
    [void]$sb.Append("<textarea id='notes-text' rows='10' placeholder='e.g. 14:20 uninstalled PC App Store, deleted leftover folder C:\Users\...\PCAppStore, removed 2 scheduled tasks, reset Chrome settings...'></textarea>")
    [void]$sb.Append("<div class='btns'><button id='save-report' class='primary'>Save report</button><button id='expand-all'>Expand all sections</button><button id='collapse-all'>Collapse all sections</button><button onclick='window.print()'>Print / PDF</button></div></section>")

    # detail sections
    $tid = 0
    foreach ($x in $script:Sections) {
        $fs = @($script:Findings | Where-Object { $_.Section -eq $x.Id -and $_.Severity -ne 'Info' })
        $worst = Get-MaxSeverity @($fs | ForEach-Object { $_.Severity })
        $badge = if ($worst) { "<span class='pill $(ConvertTo-FlagClass $worst)'>$($fs.Count) issue(s)</span>" } else { "<span class='pill good'>OK</span>" }
        [void]$sb.Append("<details class='sec' id='sec-$($x.Id)'><summary><span class='stitle'>" + (HE $x.Title) + "</span> $badge</summary><div class='sbody'>")
        if ($x.Intro) { [void]$sb.Append("<p class='intro'>" + (HE $x.Intro) + '</p>') }
        foreach ($b in $x.Blocks) { $tid++; [void]$sb.Append((Get-BlockHtml $b "t$tid")) }
        [void]$sb.Append('</div></details>')
    }

    # footer
    [void]$sb.Append("<footer><details><summary>Scanner log</summary><div class='tw'><table class='data'><thead><tr><th>Module</th><th>Seconds</th><th>Result</th></tr></thead><tbody>")
    foreach ($m in $script:ModuleLog) {
        $c = if ($m.Result -ne 'OK') { " class='f-medium'" } else { '' }
        [void]$sb.Append("<tr$c><td>" + (HE $m.Module) + '</td><td>' + ('{0:N1}' -f $m.Seconds) + '</td><td>' + (HE $m.Result) + '</td></tr>')
    }
    [void]$sb.Append('</tbody></table></div></details>')
    [void]$sb.Append("<p class='muted'>PC Health Scan v$($Meta.Version) by TCPeep (github.com/TCPeep/PC-Health-Scan, free software under GPL-3.0) &middot; look-back window $($Meta.Days) days &middot; SHA256 links open a VirusTotal <i>search</i>; nothing is uploaded. Web addresses in this report are deliberately not clickable.</p></footer>")
    [void]$sb.Append('</main><script>' + $script:ReportJs + '</script></body></html>')

    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
}

$script:ReportCss = @'
:root{--bg:#f5f6f8;--panel:#fff;--text:#1c2230;--muted:#5f6878;--border:#e1e4ea;--accent:#2d6cdf;--code:#eef0f4;
--critical:#a1162a;--critical-bg:#fde8ec;--high:#c03d0b;--high-bg:#fff0e5;--medium:#946200;--medium-bg:#fff6d9;--low:#2457c5;--low-bg:#e9f0ff;--info:#5f6878;--info-bg:#eef0f4;--good:#167a3e;--good-bg:#e5f6ec}
@media (prefers-color-scheme: dark){:root{--bg:#101318;--panel:#191c23;--text:#e5e8ee;--muted:#98a1b1;--border:#2a2f3a;--accent:#76a5ff;--code:#232833;
--critical:#ff7085;--critical-bg:#3b1219;--high:#ff9b63;--high-bg:#3a1f10;--medium:#f0c34e;--medium-bg:#33290c;--low:#86aaff;--low-bg:#162342;--info:#98a1b1;--info-bg:#222733;--good:#5fd48d;--good-bg:#11301d}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px}
header.top{background:linear-gradient(135deg,#1d3f8f,#2d6cdf);color:#fff;padding:28px 0 22px}
header .brand{font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.85}
header h1{margin:4px 0 6px;font-size:30px}header .meta{font-size:14px;opacity:.92}header .warn{color:#ffe08a}
h2{font-size:21px;margin:30px 0 12px}h3{font-size:16px;margin:18px 0 8px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:-14px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.score{text-align:center}.score .lbl{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.score .grade{font-size:44px;font-weight:700;line-height:1.1}.score .num{color:var(--muted);font-size:13px}
.tone-good .grade{color:var(--good)}.tone-low .grade{color:var(--low)}.tone-medium .grade{color:var(--medium)}.tone-high .grade{color:var(--high)}.tone-critical .grade{color:var(--critical)}
.counts{display:grid;grid-template-columns:1fr 1fr;gap:6px 14px;align-content:center;grid-column:span 2}
.cnt{display:flex;justify-content:space-between;align-items:center}.cnt b{font-size:20px}
.exec{background:var(--panel);border-left:4px solid var(--accent);padding:12px 16px;border-radius:8px;margin:16px 0}
.toc{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 4px}.toc a{font-size:13px;padding:4px 10px;border-radius:999px;background:var(--panel);border:1px solid var(--border);color:var(--text);text-decoration:none}
.toc a:hover{border-color:var(--accent)}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px;white-space:nowrap}
.pill.critical{background:var(--critical-bg);color:var(--critical)}.pill.high{background:var(--high-bg);color:var(--high)}.pill.medium{background:var(--medium-bg);color:var(--medium)}
.pill.low{background:var(--low-bg);color:var(--low)}.pill.info{background:var(--info-bg);color:var(--info)}.pill.good{background:var(--good-bg);color:var(--good)}
.shead{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:999px;padding:4px 12px;cursor:pointer;font:inherit;font-size:13px}
.chip.off{opacity:.4;text-decoration:line-through}
.finding{background:var(--panel);border:1px solid var(--border);border-left:5px solid var(--info);border-radius:10px;padding:12px 16px;margin:10px 0}
.finding.sev-critical{border-left-color:var(--critical)}.finding.sev-high{border-left-color:var(--high)}.finding.sev-medium{border-left-color:var(--medium)}.finding.sev-low{border-left-color:var(--low)}
.finding.isdone{opacity:.55}.finding.isdone h3{text-decoration:line-through}
.finding h3{margin:6px 0 4px}.finding p{margin:6px 0}
.fhead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.cat{font-size:12px;color:var(--muted)}
.done{margin-left:auto;font-size:13px;cursor:pointer;user-select:none}
.why{color:var(--muted)}.fix{background:var(--good-bg);border-radius:6px;padding:6px 10px}
.ev summary{cursor:pointer;color:var(--muted);font-size:13px}.ev ul{margin:6px 0;padding-left:18px}
code{background:var(--code);padding:1px 5px;border-radius:4px;font:12.5px/1.45 Consolas,"Cascadia Mono",monospace;word-break:break-all}
.more{font-size:13px;color:var(--accent);text-decoration:none}
.infos{margin-top:14px}.infos>summary{cursor:pointer;color:var(--muted);font-weight:600}
.passes{list-style:none;padding:0;columns:2 380px;column-gap:24px}.passes li{break-inside:avoid;padding:3px 0}.ok{color:var(--good);font-weight:700}
.muted{color:var(--muted)}
#notes textarea{width:100%;font:14px/1.5 Consolas,"Cascadia Mono",monospace;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:10px}
.btns{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.btns button{font:inherit;font-size:14px;padding:7px 14px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer}
.btns button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.actions{padding-left:18px}
details.sec{background:var(--panel);border:1px solid var(--border);border-radius:10px;margin:10px 0}
details.sec>summary{cursor:pointer;padding:12px 16px;display:flex;align-items:center;gap:10px;list-style:none}
details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"\25B8";color:var(--muted);transition:transform .15s}details.sec[open]>summary::before{transform:rotate(90deg)}
.stitle{font-weight:600;font-size:17px}.sbody{padding:0 16px 16px;border-top:1px solid var(--border)}
.intro{color:var(--muted)}.bnote{color:var(--muted);font-size:13.5px;margin:4px 0 8px}
.note{padding:8px 12px;border-radius:6px;background:var(--info-bg)}.note.tone-warn{background:var(--medium-bg)}.note.tone-bad{background:var(--high-bg)}.note.tone-good{background:var(--good-bg)}
.empty{color:var(--muted);font-style:italic}
.count{font-size:12px;color:var(--muted);font-weight:400;background:var(--code);padding:1px 7px;border-radius:999px}
.tfilter{width:100%;max-width:340px;padding:6px 10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);margin:2px 0 8px;font:inherit;font-size:14px}
.tw{overflow-x:auto;border:1px solid var(--border);border-radius:8px}
table.data{border-collapse:collapse;width:100%;font-size:13px}
table.data th{position:sticky;top:0;background:var(--code);text-align:left;padding:7px 9px;cursor:pointer;white-space:nowrap;user-select:none}
table.data th[data-sort=asc]::after{content:" \25B4"}table.data th[data-sort=desc]::after{content:" \25BE"}
table.data td{padding:6px 9px;border-top:1px solid var(--border);vertical-align:top;max-width:520px;word-break:break-word}
table.kv td:first-child{width:240px;color:var(--muted);white-space:nowrap}
tr.f-critical td{background:var(--critical-bg)}tr.f-high td{background:var(--high-bg)}tr.f-medium td{background:var(--medium-bg)}tr.f-low td{background:var(--low-bg)}tr.f-good td{background:var(--good-bg)}
a.hash{color:var(--accent);font-family:Consolas,monospace}
footer{margin:30px 0 40px;font-size:13px}footer summary{cursor:pointer;color:var(--muted)}
@media (max-width:640px){header h1{font-size:24px}.counts{grid-column:span 1;grid-template-columns:1fr}table.kv td:first-child{white-space:normal;width:auto}}
@media print{header.top{background:#1d3f8f!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.btns,.tfilter,.chips,.toc,#notes textarea:placeholder-shown{display:none}details.sec{break-inside:auto}}
'@

$script:ReportJs = @'
(function(){
var RID=document.body.getAttribute('data-rid');
function st(k,v){try{localStorage.setItem(RID+':'+k,v)}catch(e){}}
function ld(k){try{return localStorage.getItem(RID+':'+k)}catch(e){return null}}
function num(s){var m=s.replace(/,/g,'').match(/^(-?[\d.]+)\s*(B|KB|MB|GB|TB|%)?$/);if(!m)return null;var f={B:1,KB:1024,MB:1048576,GB:1073741824,TB:1099511627776}[m[2]]||1;return parseFloat(m[1])*f}
document.querySelectorAll('table.data thead th').forEach(function(th){th.addEventListener('click',function(){
 var t=th.closest('table'),tb=t.tBodies[0],i=Array.prototype.indexOf.call(th.parentNode.children,th),asc=th.getAttribute('data-sort')!=='asc';
 th.parentNode.querySelectorAll('th').forEach(function(x){x.removeAttribute('data-sort')});th.setAttribute('data-sort',asc?'asc':'desc');
 var rows=Array.prototype.slice.call(tb.rows);
 rows.sort(function(a,b){var x=(a.cells[i]||{}).innerText||'',y=(b.cells[i]||{}).innerText||'';x=x.trim();y=y.trim();var nx=num(x),ny=num(y);
  var c=(nx!==null&&ny!==null)?nx-ny:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return asc?c:-c});
 rows.forEach(function(r){tb.appendChild(r)})})});
document.querySelectorAll('input.tfilter').forEach(function(inp){inp.addEventListener('input',function(){
 var q=inp.value.toLowerCase(),t=document.getElementById(inp.getAttribute('data-target'));
 Array.prototype.forEach.call(t.tBodies[0].rows,function(r){r.style.display=r.innerText.toLowerCase().indexOf(q)>=0?'':'none'})})});
document.querySelectorAll('.chip[data-sev]').forEach(function(c){c.addEventListener('click',function(){c.classList.toggle('off');
 var off=Array.prototype.map.call(document.querySelectorAll('.chip.off'),function(x){return x.getAttribute('data-sev')});
 document.querySelectorAll('#findings > .finding').forEach(function(f){f.style.display=off.indexOf(f.getAttribute('data-sev'))>=0?'none':''})})});
var notes=document.getElementById('notes-text');var sn=ld('notes');if(sn!==null&&sn!==''){notes.value=sn}
notes.addEventListener('input',function(){st('notes',notes.value)});
document.querySelectorAll('input[data-fid]').forEach(function(cb){var id=cb.getAttribute('data-fid'),v=ld('cb:'+id);if(v!==null){cb.checked=v==='1'}
 var card=document.getElementById(id);function upd(){if(card){card.classList.toggle('isdone',cb.checked)}}upd();
 cb.addEventListener('change',function(){st('cb:'+id,cb.checked?'1':'0');upd()})});
function allSec(open){document.querySelectorAll('details.sec').forEach(function(d){d.open=open})}
document.getElementById('expand-all').addEventListener('click',function(){allSec(true)});
document.getElementById('collapse-all').addEventListener('click',function(){allSec(false)});
window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true})});
document.getElementById('save-report').addEventListener('click',function(){
 notes.textContent=notes.value;
 document.querySelectorAll('input[data-fid]').forEach(function(cb){if(cb.checked){cb.setAttribute('checked','')}else{cb.removeAttribute('checked')}});
 var html='<!DOCTYPE html>\n'+document.documentElement.outerHTML;
 var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([html],{type:'text/html'}));
 a.download=document.body.getAttribute('data-file')||'report.html';document.body.appendChild(a);a.click();
 setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},1500)});
if(location.hash){var el=document.querySelector(location.hash);if(el&&el.tagName==='DETAILS'){el.open=true}}
document.querySelectorAll('a[href^="#sec-"]').forEach(function(a){a.addEventListener('click',function(){var d=document.querySelector(a.getAttribute('href'));if(d){d.open=true}})});
})();
'@
