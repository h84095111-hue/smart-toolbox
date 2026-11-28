"""PyQt6 UI for individual and all-in-one passive OSINT collection."""
import json
from PyQt6.QtCore import QThread,pyqtSignal
from PyQt6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QComboBox,QLineEdit,QPushButton,QPlainTextEdit,QMessageBox,QDialog,QTableWidget,QTableWidgetItem,QHeaderView
from .collectors.all_in_one import run_all, run_selected
from .workflow import run_identity_workflow, CancellationToken
from .source_catalog import list_sources

class _Task(QThread):
    done=pyqtSignal(object); failed=pyqtSignal(str)
    def __init__(self,fn,*args): super().__init__(); self.fn=fn; self.args=args
    def run(self):
        try:self.done.emit(self.fn(*self.args))
        except Exception as e:self.failed.emit(str(e))

class IntegrationsPanel(QWidget):
    finding_ready=pyqtSignal(object)
    workflow_ready=pyqtSignal(object)
    def __init__(self,parent=None):
        super().__init__(parent); self.latest=None; self.task=None; self.cancellation=None
        v=QVBoxLayout(self); v.setSpacing(12)
        title=QLabel("Passive OSINT collection"); title.setStyleSheet("font-size:21px;font-weight:800"); v.addWidget(title)
        note=QLabel("Run one source or orchestrate all relevant passive sources for a domain, public IP or URL. Missing provider keys are skipped; source errors do not stop the rest of the scan.")
        note.setWordWrap(True); note.setObjectName("muted"); v.addWidget(note)
        row=QHBoxLayout(); self.target=QLineEdit(); self.target.setPlaceholderText("domain · public IP · URL · username · email"); row.addWidget(self.target,3)
        self.all_button=QPushButton("⚡  All-in-One Passive Scan"); self.all_button.setObjectName("primary"); self.all_button.clicked.connect(self.run_all_sources); row.addWidget(self.all_button,2)
        self.cancel_button=QPushButton("Stop run"); self.cancel_button.setEnabled(False); self.cancel_button.clicked.connect(self.cancel_run); row.addWidget(self.cancel_button); v.addLayout(row)
        identity_row=QHBoxLayout()
        self.identity_type=QComboBox(); self.identity_type.addItems(["Username","Email","Phone","Profile URL"]); identity_row.addWidget(self.identity_type,1)
        self.site_limit=QComboBox(); self.site_limit.addItem("500 sites",500); self.site_limit.addItem("1,000 sites",1000); self.site_limit.addItem("2,000 sites",2000); self.site_limit.addItem("3,000 sites",3000); identity_row.addWidget(self.site_limit,1)
        self.identity_type.currentTextChanged.connect(lambda kind: self.site_limit.setEnabled(kind=="Username"))
        self.identity_button=QPushButton("🔎  No-API Identity Check"); self.identity_button.clicked.connect(self.run_identity_check); identity_row.addWidget(self.identity_button,2)
        v.addLayout(identity_row)
        row2=QHBoxLayout(); self.source=QComboBox(); self.source.addItems(["Certificate transparency (crt.sh)","Wayback Machine","VirusTotal domain","AbuseIPDB public IP","urlscan.io domain","AlienVault OTX domain","Shodan existing IP data","Censys existing IP data","SecurityTrails passive DNS","GDELT public news","Public username reference links","Authorized breach-check workflow","MISP exact IOC search","Have I Been Pwned email lookup","OpenCorporates company search","CourtListener opinion search","OpenSanctions candidate search"]); row2.addWidget(self.source,2)
        self.misp=QLineEdit(); self.misp.setPlaceholderText("Optional MISP HTTPS base URL"); row2.addWidget(self.misp,2)
        self.run_button=QPushButton("Run selected source"); self.run_button.clicked.connect(self.run_lookup); row2.addWidget(self.run_button); catalogue=QPushButton("Source catalogue"); catalogue.clicked.connect(self.show_catalogue); row2.addWidget(catalogue); v.addLayout(row2)
        self.output=QPlainTextEdit(); self.output.setReadOnly(True); self.output.setPlaceholderText("Scan progress, source status and findings appear here…"); v.addWidget(self.output,1)
        self.add_button=QPushButton("Add selected-source result to active case"); self.add_button.setEnabled(False); self.add_button.clicked.connect(self.add_result); v.addWidget(self.add_button)
        self._busy=False
    def set_busy(self,busy):
        self._busy=busy
        self.all_button.setEnabled(not busy); self.run_button.setEnabled(not busy); self.identity_button.setEnabled(not busy); self.cancel_button.setEnabled(busy)
        if busy:self.add_button.setEnabled(False)
    def cancel_run(self):
        if self.cancellation:self.cancellation.cancel()
        self.output.appendPlainText("\\nCancellation requested. Running isolated collectors are being terminated…")
    def run_all_sources(self):
        value=self.target.text().strip()
        if not value: QMessageBox.information(self,"Target required","Enter a domain, public IP or URL."); return
        self.set_busy(True); self.output.setPlainText("ALL-IN-ONE PASSIVE SCAN\nTarget: "+value+"\n\nStarting relevant sources…")
        self.cancellation=CancellationToken()
        self.task=_Task(run_all,value,self.misp.text().strip(),self.cancellation)
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
        self.cancellation=CancellationToken()
        self.task=_Task(lambda: run_identity_workflow(kind,value,cancellation=self.cancellation,**options))
        self.task.done.connect(self.identity_complete)
        self.task.failed.connect(self.fail)
        self.task.finished.connect(lambda:self.set_busy(False))
        self.task.start()
    def identity_complete(self,workflow_result):
        self.workflow_ready.emit(workflow_result)
        result=workflow_result.get("result",{})
        if not result:
            self.output.setPlainText("Identity workflow did not return a result.\\n"+json.dumps(workflow_result.get("failures",[]),indent=2))
            self.latest=None
            self.add_button.setEnabled(False)
            return
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
    def show_catalogue(self):
        dialog=QDialog(self); dialog.setWindowTitle("Smart Intel source catalogue"); dialog.resize(900,560)
        layout=QVBoxLayout(dialog)
        summary=QLabel("Implemented means a callable connector is wired into the workflow. Planned, licensed and manual entries are catalogue metadata only.")
        summary.setWordWrap(True); layout.addWidget(summary)
        sources=list_sources()
        table=QTableWidget(len(sources),6); table.setHorizontalHeaderLabels(["Source","Category","Access","Status","Credential environment","Notes"])
        table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(5,QHeaderView.ResizeMode.Stretch)
        for row,source in enumerate(sources):
            values=[source["name"],source["category"],source["access"],source["status"],", ".join(source.get("auth_env",[])),source.get("notes","")]
            for col,value in enumerate(values): table.setItem(row,col,QTableWidgetItem(str(value)))
        layout.addWidget(table); close=QPushButton("Close"); close.clicked.connect(dialog.accept); layout.addWidget(close)
        dialog.exec()
    def run_lookup(self):
        value=self.target.text().strip()
        if not value: QMessageBox.information(self,"Target required","Enter a lookup value."); return
        source_ids={
            "Certificate transparency (crt.sh)":"crtsh",
            "Wayback Machine":"wayback",
            "VirusTotal domain":"virustotal",
            "AbuseIPDB public IP":"abuseipdb",
            "urlscan.io domain":"urlscan",
            "AlienVault OTX domain":"otx",
            "Shodan existing IP data":"shodan",
            "Censys existing IP data":"censys",
            "SecurityTrails passive DNS":"securitytrails",
            "GDELT public news":"gdelt",
            "Public username reference links":"public_username_reference",
            "Authorized breach-check workflow":"email_authorized_check_guidance",
            "MISP exact IOC search":"misp_exact_ioc",
            "Have I Been Pwned email lookup":"hibp",
            "OpenCorporates company search":"opencorporates",
            "CourtListener opinion search":"courtlistener",
            "OpenSanctions candidate search":"opensanctions",
        }
        source_id=source_ids[self.source.currentText()]
        self.set_busy(True); self.output.setPlainText("Selected source workflow running…")
        self.cancellation=CancellationToken()
        self.task=_Task(run_selected,value,source_id,self.misp.text().strip(),self.cancellation)
        self.task.done.connect(self.selected_complete); self.task.failed.connect(self.fail)
        self.task.finished.connect(lambda:self.set_busy(False)); self.task.start()
    def selected_complete(self,result):
        self.workflow_ready.emit(result)
        findings=result.get("findings",[])
        if findings:
            self.complete(findings[0])
            return
        details=result.get("failures",[])+result.get("skipped",[])
        self.latest=None; self.add_button.setEnabled(False)
        self.output.setPlainText("No finding returned.\\n"+("\\n".join(details) if details else "The selected source is not registered for this target type or requires configuration."))
    def complete(self,item):
        self.latest=item; self.output.setPlainText(f"{item['title']}\nSource: {item['source']}\nURL: {item['url']}\nConfidence: {item['confidence']}\n\n{item['content']}"); self.add_button.setEnabled(True)
    def fail(self,msg): self.output.setPlainText("Lookup failed: "+msg); self.add_button.setEnabled(False)
    def add_result(self):
        if self.latest:self.finding_ready.emit(self.latest)
