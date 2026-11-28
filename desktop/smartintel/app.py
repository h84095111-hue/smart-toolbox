import sys, html
from pathlib import Path
from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import *
from .storage import Store
from .models import Evidence
from .collectors.passive import collect_domain, collect_ip, collect_website
from .providers.ai import analyze, save_api_key, get_api_key, delete_api_key
from .integrations_panel import IntegrationsPanel
from .graph_panel import IdentityGraphPanel
from .evidence_integrity import append_audit, verify_audit
from .secure_vault import make_warc_record
import tempfile
from .exports import export_json, export_csv, export_stix, export_pdf, export_docx
from .config import APP_DIR

STYLE="""QWidget{background:#0a1020;color:#e7ecf7;font-family:Segoe UI,Inter,Arial;font-size:13px;selection-background-color:#6558df;selection-color:#fff}
QMainWindow,QDialog{background:#0a1020}
QFrame#sidebar{background:#0d1729;border-right:1px solid #202e48}
QLabel#brand{font-size:22px;font-weight:900;padding:10px;color:#fff;letter-spacing:1px}
QLabel#muted{color:#91a2bd} QLabel#heading{font-size:26px;font-weight:850;color:#fff}
QLabel#eyebrow{color:#a99fff;font-size:10px;font-weight:900;letter-spacing:2px}
QPushButton{background:#17243a;border:1px solid #2b3c59;border-radius:9px;padding:10px 13px;text-align:left;color:#e8edfa}
QPushButton:hover{background:#223452;border-color:#786dff}
QPushButton:pressed{background:#302b68}
QPushButton:disabled{color:#68758c;background:#111b2b;border-color:#202c40}
QPushButton#primary{background:#6256dc;border:1px solid #8a80ff;color:#fff;font-weight:800}
QPushButton#primary:hover{background:#7669f0;border-color:#aaa2ff}
QLineEdit,QTextEdit,QPlainTextEdit,QComboBox,QListWidget,QTextBrowser{background:#0d192b;border:1px solid #2a3b59;border-radius:8px;padding:9px;color:#e7ecf7}
QLineEdit:focus,QTextEdit:focus,QPlainTextEdit:focus,QComboBox:focus{border:1px solid #8579ff}
QComboBox::drop-down{border:0;width:24px}
QComboBox QAbstractItemView{background:#111e32;color:#e7ecf7;selection-background-color:#4e4798;border:1px solid #344766}
QListWidget::item{padding:8px;border-radius:6px}
QListWidget::item:selected{background:#29275a;color:#fff}
QTableWidget{background:#0d192b;border:1px solid #2a3b59;gridline-color:#202f48;alternate-background-color:#111f34;color:#e7ecf7;selection-background-color:#35316e}
QTableWidget::item{padding:7px}
QHeaderView::section{background:#15243a;color:#aebbd0;padding:10px;border:0;border-right:1px solid #253650;font-weight:700}
QTabWidget::pane{border:1px solid #253650;border-radius:10px;background:#0c1728;top:-1px}
QTabBar::tab{background:#111e32;color:#91a2bd;padding:11px 17px;margin-right:4px;border-top-left-radius:7px;border-top-right-radius:7px}
QTabBar::tab:hover{background:#1c2b45;color:#fff}
QTabBar::tab:selected{background:#302d69;color:#fff;font-weight:800;border-bottom:2px solid #9b91ff}
QScrollBar:vertical{background:#0d1728;width:10px;margin:0;border:0}
QScrollBar::handle:vertical{background:#344563;min-height:25px;border-radius:5px}
QScrollBar::handle:vertical:hover{background:#6256dc}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}
QToolTip{background:#1b2940;color:#fff;border:1px solid #485c7c;padding:5px}
QMessageBox{background:#101c30}
QCheckBox{spacing:8px;color:#dce5f5}
QGroupBox{border:1px solid #2a3b59;border-radius:9px;margin-top:12px;padding:12px;font-weight:700}
QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 5px;color:#aaa0ff}
"""

class Worker(QThread):
    done=pyqtSignal(object); failed=pyqtSignal(str)
    def __init__(self,fn,*args): super().__init__(); self.fn=fn; self.args=args
    def run(self):
        try:self.done.emit(self.fn(*self.args))
        except Exception as e:self.failed.emit(str(e))

class SettingsDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle("AI provider settings"); self.setMinimumWidth(470)
        v=QVBoxLayout(self); v.addWidget(QLabel("API keys are saved in your OS credential store using keyring."))
        self.fields={}
        for p in ("OpenAI","Gemini","Claude","virustotal","abuseipdb","otx","shodan","censys","securitytrails","misp"):
            v.addWidget(QLabel(({"virustotal":"VirusTotal","abuseipdb":"AbuseIPDB","otx":"AlienVault OTX","shodan":"Shodan","censys":"Censys","securitytrails":"SecurityTrails","misp":"MISP"}).get(p,p)+" API key")); row=QHBoxLayout(); e=QLineEdit(); e.setEchoMode(QLineEdit.EchoMode.Password); e.setText(get_api_key(p) or ""); row.addWidget(e)
            clear=QPushButton("Clear"); clear.clicked.connect(lambda _,provider=p,field=e:self.clear(provider,field)); row.addWidget(clear); v.addLayout(row); self.fields[p]=e
        note=QLabel("AI and OSINT provider usage may be billed separately. Keys are stored in your OS credential store."); note.setObjectName("muted"); v.addWidget(note)
        save=QPushButton("Save keys"); save.setObjectName("primary"); save.clicked.connect(self.save); v.addWidget(save)
    def clear(self,p,e):
        try:delete_api_key(p)
        except Exception:pass
        e.clear()
    def save(self):
        try:
            for p,e in self.fields.items():
                if e.text().strip():save_api_key(p,e.text())
            QMessageBox.information(self,"Saved","API keys saved to the OS credential store."); self.accept()
        except Exception as e:QMessageBox.critical(self,"Key storage error",str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.store=Store(); self.case_id=None; self.worker=None
        self.setWindowTitle("Smart Intel — AI OSINT Workstation"); self.resize(1280,820); self.setMinimumSize(950,650)
        root=QWidget(); row=QHBoxLayout(root); row.setContentsMargins(0,0,0,0); row.setSpacing(0)
        side=QFrame(); side.setObjectName("sidebar"); side.setFixedWidth(245); sv=QVBoxLayout(side); sv.setContentsMargins(16,20,16,16)
        brand=QLabel("◈  SMART INTEL"); brand.setObjectName("brand"); sv.addWidget(brand)
        sub=QLabel("AI OSINT WORKSTATION"); sub.setObjectName("eyebrow"); sv.addWidget(sub); sv.addSpacing(20)
        self.case_label=QLabel("NO ACTIVE CASE"); self.case_label.setObjectName("muted"); sv.addWidget(self.case_label)
        self.case_list=QListWidget(); self.case_list.currentRowChanged.connect(self.case_selected); sv.addWidget(self.case_list,1)
        new=QPushButton("+  New investigation"); new.setObjectName("primary"); new.clicked.connect(self.new_case); sv.addWidget(new)
        self.nav=[]
        for text,idx in [("⌕  Collect intelligence",0),("◉  OSINT source hub",1),("▤  Evidence & timeline",2),("⌘  AI analyst",3),("▤  Reports",4),("◎  Identity graph",5)]:
            b=QPushButton(text); b.clicked.connect(lambda _,i=idx:self.tabs.setCurrentIndex(i)); sv.addWidget(b)
        settings=QPushButton("⚙  AI provider settings"); settings.clicked.connect(lambda:SettingsDialog(self).exec()); sv.addWidget(settings)
        privacy=QLabel("● PASSIVE PUBLIC-SOURCE MODE\nNo login attempts · No exploitation\nEvidence stored locally"); privacy.setStyleSheet("color:#8fe0bd;background:#142b30;border:1px solid #28534f;border-radius:8px;padding:12px;font-size:11px"); sv.addWidget(privacy)
        row.addWidget(side)
        main=QWidget(); mv=QVBoxLayout(main); mv.setContentsMargins(25,20,25,18)
        top=QHBoxLayout(); eyebrow=QLabel("INTELLIGENCE WORKSPACE"); eyebrow.setObjectName("eyebrow"); top.addWidget(eyebrow); top.addStretch()
        self.status=QLabel("Ready"); self.status.setObjectName("muted"); top.addWidget(self.status); mv.addLayout(top)
        hero=QLabel("Investigate the public web.\nConnect evidence. Find the signal."); hero.setObjectName("heading"); hero.setStyleSheet("background:#182449;border:1px solid #38457a;border-radius:12px;padding:18px"); mv.addWidget(hero)
        self.tabs=QTabWidget(); self.tabs.addTab(self.collect_tab(),"Collect"); self.integrations=IntegrationsPanel(); self.integrations.finding_ready.connect(self.integration_done); self.integrations.workflow_ready.connect(self.workflow_done); self.tabs.addTab(self.integrations,"OSINT Sources"); self.tabs.addTab(self.evidence_tab(),"Evidence & Timeline"); self.tabs.addTab(self.ai_tab(),"AI Analyst"); self.tabs.addTab(self.report_tab(),"Reports"); self.graph_panel=IdentityGraphPanel(self.store); self.tabs.addTab(self.graph_panel,"Identity Graph"); mv.addWidget(self.tabs,1)
        row.addWidget(main,1); self.setCentralWidget(root); self.refresh_cases()
        if self.case_list.count():self.case_list.setCurrentRow(0)
        else:self.new_case()
    def require_case(self):
        if not self.case_id:QMessageBox.information(self,"Create a case","Create an investigation first."); return False
        return True
    def collect_tab(self):
        w=QWidget(); v=QVBoxLayout(w); intro=QLabel("Passive public-source collection. Select a target type and run a lookup."); intro.setObjectName("muted"); v.addWidget(intro)
        r=QHBoxLayout(); self.target_type=QComboBox(); self.target_type.addItems(["Domain","Public IP address","Website URL"]); self.target=QLineEdit(); self.target.setPlaceholderText("example.com"); r.addWidget(self.target_type); r.addWidget(self.target,1)
        self.collect_btn=QPushButton("Collect evidence"); self.collect_btn.setObjectName("primary"); self.collect_btn.clicked.connect(self.collect); r.addWidget(self.collect_btn); self.all_scan_btn=QPushButton("All-in-One scan"); self.all_scan_btn.clicked.connect(self.run_all_from_collect); r.addWidget(self.all_scan_btn); v.addLayout(r)
        self.collect_log=QPlainTextEdit(); self.collect_log.setReadOnly(True); self.collect_log.setPlaceholderText("Collection output appears here…"); v.addWidget(self.collect_log,1)
        hint=QLabel("DNS · RDAP · TLS certificate · public website metadata, headers and links. No active scanning."); hint.setObjectName("muted"); v.addWidget(hint); return w
    def run_all_from_collect(self):
        self.tabs.setCurrentIndex(1)
        self.integrations.target.setText(self.target.text().strip())
        self.integrations.run_all_sources()
    def workflow_done(self,result):
        if not self.require_case(): return
        self.store.workflow_events(self.case_id,result.get("run_id","unknown"),result.get("events",[]))
        append_audit(APP_DIR/"audit.jsonl",{"action":"workflow_completed","case_id":self.case_id,"run_id":result.get("run_id"),"status":result.get("status"),"event_count":len(result.get("events",[]))})
        self.status.setText("Workflow events saved to case audit")
    def integration_done(self, finding):
        if not self.require_case(): return
        item=Evidence(self.case_id,finding.get("source","Unknown"),finding.get("title","OSINT finding"),finding.get("url",""),finding.get("content",""),confidence=finding.get("confidence","Medium"),kind=finding.get("kind","Passive OSINT"))
        self.store.add_evidence(item)
        append_audit(APP_DIR/"audit.jsonl",{"action":"evidence_added","case_id":self.case_id,"evidence_id":item.id,"source":item.source,"title":item.title})
        self.refresh_evidence(); self.graph_panel.refresh(); self.status.setText("OSINT finding added to case")
    def evidence_tab(self):
        w=QWidget(); v=QVBoxLayout(w); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Observed UTC","Title","Source","Confidence","URL"])
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch); self.table.horizontalHeader().setSectionResizeMode(4,QHeaderView.ResizeMode.Stretch); self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.table.itemSelectionChanged.connect(self.show_evidence); v.addWidget(self.table,2)
        self.detail=QPlainTextEdit(); self.detail.setReadOnly(True); v.addWidget(self.detail,1)
        vault_group=QGroupBox("Evidence vault — encrypted payloads and attachments")
        vault_layout=QVBoxLayout(vault_group)
        self.vault_status_label=QLabel("Evidence payload encryption is not enabled.")
        self.vault_status_label.setWordWrap(True); vault_layout.addWidget(self.vault_status_label)
        vault_buttons=QHBoxLayout()
        enable=QPushButton("Enable encryption"); enable.clicked.connect(self.enable_vault); vault_buttons.addWidget(enable)
        import_file=QPushButton("Import attachment"); import_file.clicked.connect(lambda:self.import_attachment("attachment")); vault_buttons.addWidget(import_file)
        import_image=QPushButton("Import screenshot"); import_image.clicked.connect(lambda:self.import_attachment("screenshot")); vault_buttons.addWidget(import_image)
        archive=QPushButton("Create WARC from file"); archive.clicked.connect(self.archive_as_warc); vault_buttons.addWidget(archive)
        export_attachment=QPushButton("Export selected"); export_attachment.clicked.connect(self.export_attachment); vault_buttons.addWidget(export_attachment)
        vault_layout.addLayout(vault_buttons)
        self.attach_table=QTableWidget(0,5); self.attach_table.setHorizontalHeaderLabels(["Filename","Type","Size","SHA-256","Added UTC"])
        self.attach_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        self.attach_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        vault_layout.addWidget(self.attach_table)
        v.addWidget(vault_group)
        audit_row=QHBoxLayout(); verify=QPushButton("Verify audit chain"); verify.clicked.connect(self.verify_audit_chain); audit_row.addWidget(verify)
        verify_db=QPushButton("Verify case event chain"); verify_db.clicked.connect(self.verify_case_event_chain); audit_row.addWidget(verify_db)
        audit_row.addStretch(); v.addLayout(audit_row); return w
    def ai_tab(self):
        w=QWidget(); v=QVBoxLayout(w); note=QLabel("Analyze evidence already collected in this case. The assistant is instructed to separate facts, inferences and unknowns."); note.setWordWrap(True); note.setObjectName("muted"); v.addWidget(note)
        r=QHBoxLayout(); self.provider=QComboBox(); self.provider.addItems(["OpenAI","Gemini","Claude"]); r.addWidget(QLabel("Provider")); r.addWidget(self.provider); r.addStretch(); v.addLayout(r)
        self.prompt=QLineEdit(); self.prompt.setPlaceholderText("Summarize evidence and identify gaps…"); v.addWidget(self.prompt)
        b=QPushButton("Analyze collected evidence"); b.setObjectName("primary"); b.clicked.connect(self.run_ai); v.addWidget(b)
        self.ai_result=QPlainTextEdit(); self.ai_result.setReadOnly(True); v.addWidget(self.ai_result,1); return w
    def report_tab(self):
        w=QWidget(); v=QVBoxLayout(w); self.preview=QTextBrowser(); v.addWidget(self.preview,1)
        r=QHBoxLayout(); b=QPushButton("Preview report"); b.clicked.connect(lambda:self.preview.setHtml(self.report_html())); r.addWidget(b)
        export=QPushButton("Export HTML"); export.setObjectName("primary"); export.clicked.connect(self.export_report); r.addWidget(export)
        for label,ext,fn in [("JSON","json",export_json),("CSV","csv",export_csv),("STIX 2.1","stix.json",export_stix),("PDF","pdf",export_pdf),("DOCX","docx",export_docx)]:
            btn=QPushButton(label); btn.clicked.connect(lambda _,e=ext,f=fn:self.export_structured(e,f)); r.addWidget(btn)
        v.addLayout(r); return w
    def refresh_cases(self):
        self.case_list.blockSignals(True); self.case_list.clear(); self.cases=self.store.cases()
        for c in self.cases:self.case_list.addItem(c["name"])
        self.case_list.blockSignals(False)
    def new_case(self):
        name,ok=QInputDialog.getText(self,"New investigation","Case name:")
        if ok and name.strip():
            cid=self.store.create_case(name.strip()); append_audit(APP_DIR/"audit.jsonl",{"action":"case_created","case_id":cid,"name":name.strip()}); self.refresh_cases()
            self.case_list.setCurrentRow(next(i for i,c in enumerate(self.cases) if c["id"]==cid))
    def case_selected(self,i):
        if i<0 or i>=len(getattr(self,"cases",[])):return
        self.case_id=self.cases[i]["id"]; self.case_label.setText("ACTIVE CASE"); self.refresh_evidence(); self.refresh_attachments(); self.graph_panel.set_case(self.case_id)
    def collect(self):
        if not self.require_case():return
        value=self.target.text().strip()
        if not value:return
        fn={"Domain":collect_domain,"Public IP address":collect_ip,"Website URL":collect_website}[self.target_type.currentText()]
        self.collect_btn.setEnabled(False); self.status.setText("Collecting…")
        self.worker=Worker(fn,value); self.worker.done.connect(self.collection_done); self.worker.failed.connect(self.failed); self.worker.finished.connect(lambda:self.collect_btn.setEnabled(True)); self.worker.start()
    def collection_done(self,findings):
        for f in findings:
            item=Evidence(self.case_id,f.source,f.title,f.url,f.value,confidence=f.confidence,kind="OSINT finding"); self.store.add_evidence(item); append_audit(APP_DIR/"audit.jsonl",{"action":"evidence_added","case_id":self.case_id,"evidence_id":item.id,"source":item.source,"title":item.title})
            self.collect_log.appendPlainText(f"\n[{f.confidence}] {f.title}\nSource: {f.source}\nURL: {f.url}\n{f.value[:4500]}")
        self.status.setText(f"Collected {len(findings)} findings"); self.refresh_evidence(); self.graph_panel.refresh()
    def failed(self,msg):self.status.setText("Task failed"); QMessageBox.warning(self,"Task failed",msg)
    def refresh_evidence(self):
        if not self.case_id:return
        self.evidence=self.store.evidence(self.case_id); self.table.setRowCount(len(self.evidence))
        for i,e in enumerate(self.evidence):
            for j,val in enumerate([e.observed_at[:19].replace("T"," "),e.title,e.source,e.confidence,e.url]):self.table.setItem(i,j,QTableWidgetItem(val))
    def show_evidence(self):
        rows=self.table.selectionModel().selectedRows()
        if rows:
            e=self.evidence[rows[0].row()]; self.detail.setPlainText(f"{e.title}\nSource: {e.source}\nURL: {e.url}\nObserved: {e.observed_at}\nConfidence: {e.confidence}\n\n{e.content}")
    def run_ai(self):
        if not self.require_case():return
        evidence=self.store.evidence(self.case_id)
        if not evidence:QMessageBox.information(self,"No evidence","Collect public-source evidence first."); return
        self.status.setText("AI analysis running…"); p=self.provider.currentText(); task=self.prompt.text().strip() or "Summarize the evidence and identify unknowns."
        self.worker=Worker(analyze,p,task,evidence); self.worker.done.connect(self.ai_done); self.worker.failed.connect(self.failed); self.worker.start()
    def ai_done(self,result):self.ai_result.setPlainText(result); self.status.setText("AI analysis complete")
    def report_html(self):
        if not self.require_case():return ""
        case=next((c for c in self.store.cases() if c["id"]==self.case_id),None); items=self.store.evidence(self.case_id); parts=[]
        for e in items:
            parts.append(f'<article><h3>{html.escape(e.title)}</h3><p><b>Source:</b> {html.escape(e.source)} · <b>Confidence:</b> {html.escape(e.confidence)} · {html.escape(e.observed_at)}</p><p><a href="{html.escape(e.url,quote=True)}">{html.escape(e.url)}</a></p><pre>{html.escape(e.content)}</pre></article>')
        return '<meta charset="utf-8"><style>body{font:15px Arial;max-width:950px;margin:35px auto;color:#243047}article{border:1px solid #ccd4df;border-radius:8px;padding:16px;margin:16px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:10px}</style>'+f'<h1>Smart Intel — {html.escape(case["name"] if case else "Case")}</h1><p>Generated {datetime.now(timezone.utc).isoformat()} · {len(items)} evidence items</p>'+''.join(parts)
    def export_structured(self,extension,exporter):
        if not self.require_case(): return
        case=next((c for c in self.store.cases() if c["id"]==self.case_id),{"name":"Smart Intel case"})
        items=[{"id":e.id,"title":e.title,"source":e.source,"url":e.url,"content":e.content,"observed_at":e.observed_at,"confidence":e.confidence,"kind":e.kind} for e in self.store.evidence(self.case_id)]
        filters={"json":"JSON (*.json)","csv":"CSV (*.csv)","stix.json":"STIX 2.1 (*.stix.json)","pdf":"PDF (*.pdf)","docx":"Word (*.docx)"}
        path,_=QFileDialog.getSaveFileName(self,"Export case",f"smart-intel-case.{extension}",filters[extension])
        if not path:return
        try:
            if exporter is export_json: exporter(case,items,path)
            elif exporter is export_stix: exporter(items,path,case.get("name","Smart Intel case"))
            elif exporter in (export_pdf,export_docx): exporter(case.get("name","Smart Intel case"),items,path)
            else: exporter(items,path)
            QMessageBox.information(self,"Exported",f"Export saved to:\n{path}")
        except Exception as exc: QMessageBox.critical(self,"Export failed",str(exc))
    def refresh_attachments(self):
        if not self.case_id or not hasattr(self,"attach_table"): return
        rows=self.store.attachments(self.case_id); self.attachments=rows; self.attach_table.setRowCount(len(rows))
        for i,item in enumerate(rows):
            values=[item["filename"],item["kind"],str(item["size"]),item["sha256"],item["created_at"][:19]]
            for j,value in enumerate(values): self.attach_table.setItem(i,j,QTableWidgetItem(value))
        status=self.store.vault_status()
        self.vault_status_label.setText(("Encrypted evidence payloads are enabled. " if status["enabled"] else "Encryption is not enabled. ")+status["scope"])
    def enable_vault(self):
        if QMessageBox.question(self,"Enable evidence encryption","Create/use an encryption key in the operating-system credential store and encrypt all existing evidence content? Keep your OS credential-store access: losing the key means losing access to encrypted evidence.") != QMessageBox.StandardButton.Yes: return
        try:
            self.store.enable_evidence_encryption()
            self.refresh_evidence(); self.refresh_attachments()
            QMessageBox.information(self,"Vault enabled","Evidence content is now encrypted at rest. Case names and other SQLite metadata remain plaintext.")
        except Exception as exc: QMessageBox.critical(self,"Vault error",str(exc))
    def import_attachment(self,kind):
        if not self.require_case(): return
        path,_=QFileDialog.getOpenFileName(self,"Import evidence attachment")
        if not path: return
        try:
            if not self.store.vault_status()["enabled"]:
                QMessageBox.information(self,"Enable encryption","Enable evidence encryption before importing files into the vault."); return
            row=self.store.add_attachment(self.case_id,path,kind=kind)
            append_audit(APP_DIR/"audit.jsonl",{"action":"attachment_added","case_id":self.case_id,"attachment_id":row["id"],"filename":row["filename"],"sha256":row["sha256"],"kind":kind})
            self.refresh_attachments(); self.status.setText("Encrypted attachment imported")
        except Exception as exc: QMessageBox.critical(self,"Import failed",str(exc))
    def archive_as_warc(self):
        if not self.require_case(): return
        source,_=QFileDialog.getOpenFileName(self,"Select file to wrap in WARC")
        if not source: return
        try:
            if not self.store.vault_status()["enabled"]:
                QMessageBox.information(self,"Enable encryption","Enable evidence encryption before creating WARC records."); return
            record=make_warc_record(source)
            with tempfile.NamedTemporaryFile(prefix="smartintel-",suffix=".warc",delete=False) as handle:
                handle.write(record); temp_path=Path(handle.name)
            try: row=self.store.add_attachment(self.case_id,temp_path,kind="warc")
            finally: temp_path.unlink(missing_ok=True)
            append_audit(APP_DIR/"audit.jsonl",{"action":"warc_imported","case_id":self.case_id,"attachment_id":row["id"],"source_filename":Path(source).name,"sha256":row["sha256"]})
            self.refresh_attachments(); self.status.setText("Encrypted WARC resource record created")
        except Exception as exc: QMessageBox.critical(self,"WARC creation failed",str(exc))
    def export_attachment(self):
        rows=self.attach_table.selectionModel().selectedRows() if hasattr(self,"attach_table") else []
        if not rows: QMessageBox.information(self,"Select attachment","Select an attachment first."); return
        item=self.attachments[rows[0].row()]
        path,_=QFileDialog.getSaveFileName(self,"Export decrypted attachment",item["filename"])
        if not path: return
        try:
            data=self.store.read_attachment(item["id"]); Path(path).write_bytes(data)
            append_audit(APP_DIR/"audit.jsonl",{"action":"attachment_exported","case_id":self.case_id,"attachment_id":item["id"],"filename":item["filename"],"sha256":item["sha256"]})
            QMessageBox.information(self,"Exported","Decrypted attachment exported.")
        except Exception as exc: QMessageBox.critical(self,"Export failed",str(exc))
    def verify_case_event_chain(self):
        ok,count=self.store.verify_event_chain()
        if ok: QMessageBox.information(self,"Case event verification",f"Database event chain valid. Verified {count} events.")
        else: QMessageBox.warning(self,"Case event verification failed",f"Database event chain invalid after {count} verified events.")
    def verify_audit_chain(self):
        ok,count=verify_audit(APP_DIR/"audit.jsonl")
        if ok: QMessageBox.information(self,"Audit verification",f"Audit chain valid. Verified {count} entries.")
        else: QMessageBox.warning(self,"Audit verification failed",f"Audit chain invalid after {count} verified entries. Preserve the journal for investigation.")
    def export_report(self):
        data=self.report_html()
        if not data:return
        path,_=QFileDialog.getSaveFileName(self,"Export report","smart-intel-report.html","HTML (*.html)")
        if path:
            try: Path(path).write_text(data,encoding="utf-8"); QMessageBox.information(self,"Exported","Report saved.")
            except Exception as exc: QMessageBox.critical(self,"Export failed",str(exc))

def main():
    app=QApplication(sys.argv); app.setApplicationName("Smart Intel"); app.setStyleSheet(STYLE); window=MainWindow(); window.show(); sys.exit(app.exec())
