"""PyQt6 panel for passive OSINT provider lookups."""
from PyQt6.QtCore import QThread,pyqtSignal
from PyQt6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QComboBox,QLineEdit,QPushButton,QPlainTextEdit,QMessageBox
from .collectors import passive_sources as src
class _Task(QThread):
    done=pyqtSignal(object); failed=pyqtSignal(str)
    def __init__(self,fn,*args): super().__init__(); self.fn=fn; self.args=args
    def run(self):
        try:self.done.emit(self.fn(*self.args))
        except Exception as e:self.failed.emit(str(e))
class IntegrationsPanel(QWidget):
    finding_ready=pyqtSignal(object)
    def __init__(self,parent=None):
        super().__init__(parent); self.latest=None; self.task=None; v=QVBoxLayout(self)
        title=QLabel("Passive OSINT source integrations"); title.setStyleSheet("font-size:20px;font-weight:800"); v.addWidget(title)
        note=QLabel("Public-source APIs and existing observations only. No port scanning, account scraping or access-control bypass."); note.setWordWrap(True); note.setStyleSheet("color:#94a4bd"); v.addWidget(note)
        row=QHBoxLayout(); self.source=QComboBox(); self.source.addItems(["Certificate transparency (crt.sh)","Wayback Machine","VirusTotal domain","AbuseIPDB public IP","urlscan.io domain","AlienVault OTX domain","Shodan existing IP data","Censys existing IP data","SecurityTrails passive DNS","GDELT public news","Public username reference links","Authorized breach-check workflow","MISP exact IOC search"]); row.addWidget(self.source,1)
        self.target=QLineEdit(); self.target.setPlaceholderText("domain, public IP, URL, username or exact IOC"); row.addWidget(self.target,2)
        self.misp=QLineEdit(); self.misp.setPlaceholderText("MISP HTTPS base URL"); row.addWidget(self.misp,1)
        self.run_button=QPushButton("Run lookup"); self.run_button.setObjectName("primary"); self.run_button.clicked.connect(self.run_lookup); row.addWidget(self.run_button); v.addLayout(row)
        self.output=QPlainTextEdit(); self.output.setReadOnly(True); v.addWidget(self.output,1)
        self.add_button=QPushButton("Add result to active case"); self.add_button.setEnabled(False); self.add_button.clicked.connect(self.add_result); v.addWidget(self.add_button)
    def run_lookup(self):
        value=self.target.text().strip()
        if not value: QMessageBox.information(self,"Target required","Enter a lookup value."); return
        mapping={"Certificate transparency (crt.sh)":(src.certificate_transparency,(value,)),"Wayback Machine":(src.wayback,(value,)),"VirusTotal domain":(src.virustotal_domain,(value,)),"AbuseIPDB public IP":(src.abuseipdb_ip,(value,)),"urlscan.io domain":(src.urlscan_search,(value,)),"AlienVault OTX domain":(src.otx_domain,(value,)),"Shodan existing IP data":(src.shodan_host,(value,)),"Censys existing IP data":(src.censys_host,(value,)),"SecurityTrails passive DNS":(src.passive_dns_history,(value,)),"GDELT public news":(src.gdelt_news,(value,)),"Public username reference links":(src.public_username_reference,(value,)),"Authorized breach-check workflow":(src.breach_check_guidance,(value,)),"MISP exact IOC search":(src.misp_search,(self.misp.text().strip(),value))}
        fn,args=mapping[self.source.currentText()]; self.run_button.setEnabled(False); self.output.setPlainText("Lookup running…")
        self.task=_Task(fn,*args); self.task.done.connect(self.complete); self.task.failed.connect(self.fail); self.task.finished.connect(lambda:self.run_button.setEnabled(True)); self.task.start()
    def complete(self,item):
        self.latest=item; self.output.setPlainText(f"{item['title']}\\nSource: {item['source']}\\nURL: {item['url']}\\nConfidence: {item['confidence']}\\n\\n{item['content']}"); self.add_button.setEnabled(True)
    def fail(self,msg): self.output.setPlainText("Lookup failed: "+msg); self.add_button.setEnabled(False)
    def add_result(self):
        if self.latest: self.finding_ready.emit(self.latest)
