"""PyQt6 UI for individual and all-in-one passive OSINT collection."""
import json
from PyQt6.QtCore import QThread,pyqtSignal
from PyQt6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QComboBox,QLineEdit,QPushButton,QPlainTextEdit,QMessageBox
from .collectors import passive_sources as src
from .collectors.all_in_one import run_all
from .identity_checks import check_identity

class _Task(QThread):
    done=pyqtSignal(object); failed=pyqtSignal(str)
    def __init__(self,fn,*args): super().__init__(); self.fn=fn; self.args=args
    def run(self):
        try:self.done.emit(self.fn(*self.args))
        except Exception as e:self.failed.emit(str(e))

class IntegrationsPanel(QWidget):
    finding_ready=pyqtSignal(object)
    def __init__(self,parent=None):
        super().__init__(parent); self.latest=None; self.task=None
        v=QVBoxLayout(self); v.setSpacing(12)
        title=QLabel("Passive OSINT collection"); title.setStyleSheet("font-size:21px;font-weight:800"); v.addWidget(title)
        note=QLabel("Run one source or orchestrate all relevant passive sources for a domain, public IP or URL. Missing provider keys are skipped; source errors do not stop the rest of the scan.")
        note.setWordWrap(True); note.setObjectName("muted"); v.addWidget(note)
        row=QHBoxLayout(); self.target=QLineEdit(); self.target.setPlaceholderText("domain · public IP · URL · username · email"); row.addWidget(self.target,3)
        self.all_button=QPushButton("⚡  All-in-One Passive Scan"); self.all_button.setObjectName("primary"); self.all_button.clicked.connect(self.run_all_sources); row.addWidget(self.all_button,2); v.addLayout(row)
        identity_row=QHBoxLayout()
        self.identity_type=QComboBox(); self.identity_type.addItems(["Username","Email","Phone","Profile URL"]); identity_row.addWidget(self.identity_type,1)
        self.site_limit=QComboBox(); self.site_limit.addItem("500 sites",500); self.site_limit.addItem("1,000 sites",1000); self.site_limit.addItem("2,000 sites",2000); self.site_limit.addItem("3,000 sites",3000); identity_row.addWidget(self.site_limit,1)
        self.identity_type.currentTextChanged.connect(lambda kind: self.site_limit.setEnabled(kind=="Username"))
        self.identity_button=QPushButton("🔎  No-API Identity Check"); self.identity_button.clicked.connect(self.run_identity_check); identity_row.addWidget(self.identity_button,2)
        v.addLayout(identity_row)
        row2=QHBoxLayout(); self.source=QComboBox(); self.source.addItems(["Certificate transparency (crt.sh)","Wayback Machine","VirusTotal domain","AbuseIPDB public IP","urlscan.io domain","AlienVault OTX domain","Shodan existing IP data","Censys existing IP data","SecurityTrails passive DNS","GDELT public news","Public username reference links","Authorized breach-check workflow","MISP exact IOC search"]); row2.addWidget(self.source,2)
        self.misp=QLineEdit(); self.misp.setPlaceholderText("Optional MISP HTTPS base URL"); row2.addWidget(self.misp,2)
        self.run_button=QPushButton("Run selected source"); self.run_button.clicked.connect(self.run_lookup); row2.addWidget(self.run_button); v.addLayout(row2)
        self.output=QPlainTextEdit(); self.output.setReadOnly(True); self.output.setPlaceholderText("Scan progress, source status and findings appear here…"); v.addWidget(self.output,1)
        self.add_button=QPushButton("Add selected-source result to active case"); self.add_button.setEnabled(False); self.add_button.clicked.connect(self.add_result); v.addWidget(self.add_button)
        self._busy=False
    def set_busy(self,busy):
        self._busy=busy
        self.all_button.setEnabled(not busy); self.run_button.setEnabled(not busy); self.identity_button.setEnabled(not busy)
        if busy:self.add_button.setEnabled(False)
    def run_all_sources(self):
        value=self.target.text().strip()
        if not value: QMessageBox.information(self,"Target required","Enter a domain, public IP or URL."); return
        self.set_busy(True); self.output.setPlainText("ALL-IN-ONE PASSIVE SCAN\nTarget: "+value+"\n\nStarting relevant sources…")
        self.task=_Task(run_all,value,self.misp.text().strip())
        self.task.done.connect(self.all_complete); self.task.failed.connect(self.fail); self.task.finished.connect(lambda:self.set_busy(False)); self.task.start()
    def all_complete(self,result):
        findings=result["findings"]; failures=result["failures"]; skipped=result["skipped"]
        lines=[f"SCAN COMPLETE — {result['target']}",f"Findings: {len(findings)}  |  Failed: {len(failures)}  |  Skipped: {len(skipped)}",""]
        for item in findings:
            lines.append(f"[{item.get('confidence','Unknown')}] {item.get('title','Finding')} — {item.get('source','')}")
        if skipped: lines.extend(["","SKIPPED / NOT CONFIGURED"]+["• "+x for x in skipped])
        if failures: lines.extend(["","SOURCE ERRORS"]+["• "+x for x in failures])
        self.output.setPlainText("\n".join(lines))
        for item in findings:self.finding_ready.emit(item)
        self.latest=None; self.add_button.setEnabled(False)
    def run_identity_check(self):
        value=self.target.text().strip()
        if not value:
            QMessageBox.information(self,"Identifier required","Enter a username, email address or phone number.")
            return
        kind=self.identity_type.currentText().lower().replace(" ","_")
        options={"max_sites":int(self.site_limit.currentData())} if kind=="username" else ({"default_region":"MY"} if kind=="phone" else {})
        self.set_busy(True)
        self.output.setPlainText(f"NO-API {kind.upper()} CHECK\\nTarget: {value}\\n\\nRunning local/public-source checks…")
        self.task=_Task(lambda: check_identity(kind,value,**options))
        self.task.done.connect(self.identity_complete)
        self.task.failed.connect(self.fail)
        self.task.finished.connect(lambda:self.set_busy(False))
        self.task.start()
    def identity_complete(self,result):
        lines=[f"IDENTITY CHECK — {result.get('identifier_type',result.get('tool',''))}",
               f"Status: {result.get('status','unknown')}"]
        if result.get("tool"):
            lines.append(f"Tool: {result['tool']} | Requested site limit: {result.get('requested_site_limit','default')}")
        if result.get("e164"): lines.append(f"Normalized: {result['e164']}")
        if result.get("domain"): lines.append(f"Mail domain: {result['domain']} | DNS: {result.get('mail_dns_status')}")
        if result.get("region"): lines.append(f"Region: {result['region']} | Number type: {result.get('number_type')}")
        profile=result.get("profile",{})
        if profile:
            lines.extend(["",f"Profile title: {profile.get('title','')}",
                          f"Display name: {profile.get('display_name','')}",
                          f"Description: {profile.get('description','')}",
                          f"Canonical URL: {profile.get('canonical_url','')}"])
        pivots=result.get("pivot_candidates",[])
        if pivots:
            lines.extend(["","PIVOT CANDIDATES — analyst approval required"])
            for pivot in pivots:
                lines.append(f"[PENDING] {pivot['username']} — {pivot['url']}")
        # Persist email, phone and profile metadata checks as case evidence.
        if result.get("identifier_type") in {"email","phone","profile_url"}:
            evidence_payload={k:v for k,v in result.items() if k not in {"stdout_tail","stderr_tail"}}
            self.finding_ready.emit({"title":"Identity check — "+str(result.get("identifier_type")),
                "content":json.dumps(evidence_payload,ensure_ascii=False,indent=2,default=str),
                "source":"Smart Intel identity checks","url":result.get("url",""),
                "confidence":"Low","kind":"Identity validation observation"})
        findings=result.get("findings",[])
        lines.extend(["",f"Candidate profiles: {len(findings)}"])
        for item in findings:
            lines.append(f"[{item.get('confidence','Unknown')}] {item.get('title','Profile')} — {item.get('url','')}")
            self.finding_ready.emit({"title":item.get("title","Username candidate"),
                "content":item.get("details","Candidate public profile; verify manually."),
                "source":item.get("source","Maigret"),"url":item.get("url",""),
                "confidence":item.get("confidence","Medium"),"kind":"Identity lead"})
        for url in result.get("public_search_urls",[]):
            lines.append("Public search: "+url)
        if result.get("install_hint"): lines.extend(["",result["install_hint"]])
        if result.get("interpretation"): lines.extend(["",result["interpretation"]])
        if result.get("limitations"): lines.extend(["",result["limitations"]])
        if result.get("stderr_tail"): lines.extend(["","Tool diagnostics:",result["stderr_tail"]])
        self.output.setPlainText("\\n".join(lines))
        self.latest=None
        self.add_button.setEnabled(False)
    def run_lookup(self):
        value=self.target.text().strip()
        if not value: QMessageBox.information(self,"Target required","Enter a lookup value."); return
        mapping={"Certificate transparency (crt.sh)":(src.certificate_transparency,(value,)),"Wayback Machine":(src.wayback,(value,)),"VirusTotal domain":(src.virustotal_domain,(value,)),"AbuseIPDB public IP":(src.abuseipdb_ip,(value,)),"urlscan.io domain":(src.urlscan_search,(value,)),"AlienVault OTX domain":(src.otx_domain,(value,)),"Shodan existing IP data":(src.shodan_host,(value,)),"Censys existing IP data":(src.censys_host,(value,)),"SecurityTrails passive DNS":(src.passive_dns_history,(value,)),"GDELT public news":(src.gdelt_news,(value,)),"Public username reference links":(src.public_username_reference,(value,)),"Authorized breach-check workflow":(src.breach_check_guidance,(value,)),"MISP exact IOC search":(src.misp_search,(self.misp.text().strip(),value))}
        fn,args=mapping[self.source.currentText()]; self.set_busy(True); self.output.setPlainText("Selected source lookup running…")
        self.task=_Task(fn,*args); self.task.done.connect(self.complete); self.task.failed.connect(self.fail); self.task.finished.connect(lambda:self.set_busy(False)); self.task.start()
    def complete(self,item):
        self.latest=item; self.output.setPlainText(f"{item['title']}\nSource: {item['source']}\nURL: {item['url']}\nConfidence: {item['confidence']}\n\n{item['content']}"); self.add_button.setEnabled(True)
    def fail(self,msg): self.output.setPlainText("Lookup failed: "+msg); self.add_button.setEnabled(False)
    def add_result(self):
        if self.latest:self.finding_ready.emit(self.latest)
