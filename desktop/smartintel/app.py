import sys, html
from pathlib import Path
from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QDesktopServices
from .storage import Store
from .models import Evidence
from .collectors.passive import collect_domain, collect_ip, collect_website
from .providers.ai import analyze, save_api_key, get_api_key, delete_api_key
from .integrations_panel import IntegrationsPanel
from .graph_panel import IdentityGraphPanel
from .evidence_integrity import append_audit, verify_audit
from .secure_vault import make_warc_record, make_warc_response
import tempfile
from .exports import export_json, export_csv, export_stix, export_pdf, export_docx
from .config import APP_DIR
from .browser_capture import capture_public_screenshot
from .image_intel import inspect_image, compare_images
from .signing import signed_export, verify_signed_export
from .monitoring_panel import MonitoringPanel
from .content_monitoring_panel import ContentMonitoringPanel
from .network import proxy_label, validate_proxy_url
from .workflow import CollectorRegistry, CollectorSpec, ExecutionPolicy, CancellationToken, run_workflow

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
        for p in ("OpenAI","Gemini","Claude","virustotal","abuseipdb","otx","shodan","censys","securitytrails","misp","hibp","opencorporates","courtlistener","opensanctions","network_proxy","telegram_bot_token"):
            label=({"virustotal":"VirusTotal","abuseipdb":"AbuseIPDB","otx":"AlienVault OTX","shodan":"Shodan","censys":"Censys","securitytrails":"SecurityTrails","misp":"MISP","hibp":"Have I Been Pwned","opencorporates":"OpenCorporates","courtlistener":"CourtListener","opensanctions":"OpenSanctions","network_proxy":"HTTP / Tor SOCKS5H proxy URL","telegram_bot_token":"Telegram Bot API token"}).get(p,p)
            v.addWidget(QLabel(label if p in {"network_proxy","telegram_bot_token"} else label+" API key")); row=QHBoxLayout(); e=QLineEdit(); e.setEchoMode(QLineEdit.EchoMode.Password); e.setText(get_api_key(p) or ""); row.addWidget(e)
            clear=QPushButton("Clear"); clear.clicked.connect(lambda _,provider=p,field=e:self.clear(provider,field)); row.addWidget(clear); v.addLayout(row); self.fields[p]=e
        note=QLabel("Keys are stored in your OS credential store. Proxy routing is opt-in; for onion sites use a running local Tor SOCKS5H listener configured as socks5h://127.0.0.1:9050. Smart Intel does not start Tor or manage VPN software. Proxy routing is not anonymity. Telegram: create a bot with BotFather, add it to the public channels you administer, then paste its token here. The Bot API delivers new channel updates only; it does not provide message history. Use a dedicated bot token for Smart Intel, and clear any configured webhook before polling."); note.setObjectName("muted"); v.addWidget(note)
        save=QPushButton("Save keys"); save.setObjectName("primary"); save.clicked.connect(self.save); v.addWidget(save)
    def clear(self,p,e):
        try:delete_api_key(p)
        except Exception:pass
        e.clear()
    def save(self):
        try:
            if self.fields.get("network_proxy") and self.fields["network_proxy"].text().strip():
                validate_proxy_url(self.fields["network_proxy"].text())
            for p,e in self.fields.items():
                if e.text().strip():save_api_key(p,e.text())
            host = self.parent()
            if host is not None and hasattr(host, "network_route_label"):
                host.network_route_label.setText("Network route: " + proxy_label() +
                    "\\nVPN is controlled by your operating system.")
            QMessageBox.information(self,"Saved","API keys and network route settings saved to the OS credential store."); self.accept()
        except Exception as e:QMessageBox.critical(self,"Key storage error",str(e))

class MainWindow(QMainWindow):
    def __init__(self, user=None):
        super().__init__(); self.store=Store(); self.current_user=user; self.case_id=None; self.worker=None
        self.setWindowTitle("Smart Intel — AI OSINT Workstation"); self.resize(1280,820); self.setMinimumSize(950,650)
        root=QWidget(); row=QHBoxLayout(root); row.setContentsMargins(0,0,0,0); row.setSpacing(0)
        side=QFrame(); side.setObjectName("sidebar"); side.setFixedWidth(245); sv=QVBoxLayout(side); sv.setContentsMargins(16,20,16,16)
        brand=QLabel("◈  SMART INTEL"); brand.setObjectName("brand"); sv.addWidget(brand)
        sub=QLabel("AI OSINT WORKSTATION"); sub.setObjectName("eyebrow"); sv.addWidget(sub); sv.addSpacing(20)
        self.case_label=QLabel("NO ACTIVE CASE"); self.case_label.setObjectName("muted"); sv.addWidget(self.case_label)
        self.case_list=QListWidget(); self.case_list.currentRowChanged.connect(self.case_selected); sv.addWidget(self.case_list,1)
        new=QPushButton("+  New investigation"); new.setObjectName("primary"); new.clicked.connect(self.new_case); sv.addWidget(new); self.new_case_button=new
        self.nav=[]
        for text,idx in [("⌕  Collect intelligence",0),("◉  OSINT source hub",1),("▤  Evidence & timeline",2),("⌘  AI analyst",3),("▤  Reports",4),("◎  Identity graph",5),("◉  Social / Telegram / Tor",7)]:
            b=QPushButton(text); b.clicked.connect(lambda _,i=idx:self.tabs.setCurrentIndex(i)); sv.addWidget(b)
        team=QPushButton("♙  Manage users"); team.clicked.connect(self.manage_team); sv.addWidget(team)
        share=QPushButton("↗  Share active case"); share.clicked.connect(self.share_case); sv.addWidget(share)
        settings=QPushButton("⚙  AI & network settings"); settings.clicked.connect(lambda:SettingsDialog(self).exec()); sv.addWidget(settings)
        privacy=QLabel("● PASSIVE PUBLIC-SOURCE MODE\nNo login attempts · No exploitation\nEvidence stored locally"); privacy.setStyleSheet("color:#8fe0bd;background:#142b30;border:1px solid #28534f;border-radius:8px;padding:12px;font-size:11px"); sv.addWidget(privacy)
        self.network_route_label=QLabel("Network route: "+proxy_label()+"\nVPN is controlled by your operating system."); self.network_route_label.setWordWrap(True); self.network_route_label.setObjectName("muted"); sv.addWidget(self.network_route_label)
        row.addWidget(side)
        main=QWidget(); mv=QVBoxLayout(main); mv.setContentsMargins(25,20,25,18)
        top=QHBoxLayout(); eyebrow=QLabel("INTELLIGENCE WORKSPACE"); eyebrow.setObjectName("eyebrow"); top.addWidget(eyebrow); top.addStretch()
        self.status=QLabel("Ready"); self.status.setObjectName("muted"); top.addWidget(self.status); mv.addLayout(top)
        hero=QLabel("Investigate the public web.\nConnect evidence. Find the signal."); hero.setObjectName("heading"); hero.setStyleSheet("background:#182449;border:1px solid #38457a;border-radius:12px;padding:18px"); mv.addWidget(hero)
        self.tabs=QTabWidget(); self.tabs.addTab(self.collect_tab(),"Collect"); self.integrations=IntegrationsPanel(); self.integrations.finding_ready.connect(self.integration_done); self.integrations.workflow_ready.connect(self.workflow_done); self.tabs.addTab(self.integrations,"OSINT Sources"); self.tabs.addTab(self.evidence_tab(),"Evidence & Timeline"); self.tabs.addTab(self.ai_tab(),"AI Analyst"); self.tabs.addTab(self.report_tab(),"Reports"); self.graph_panel=IdentityGraphPanel(self.store); self.tabs.addTab(self.graph_panel,"Identity Graph"); self.monitoring_panel=MonitoringPanel(self.store,self.current_user); self.monitoring_panel.evidence_added.connect(self.monitoring_evidence_added); self.tabs.addTab(self.monitoring_panel,"Monitoring"); self.content_monitor_panel=ContentMonitoringPanel(self.store,self.current_user); self.content_monitor_panel.evidence_added.connect(self.monitoring_evidence_added); self.tabs.addTab(self.content_monitor_panel,"Social / Telegram / Tor"); mv.addWidget(self.tabs,1)
        row.addWidget(main,1); self.setCentralWidget(root); self.refresh_cases()
        if self.case_list.count():self.case_list.setCurrentRow(0)
        elif self.current_user and self.current_user.get("role") in {"admin","analyst"}:self.new_case()
        else:QMessageBox.information(self,"No shared cases","This account has no cases assigned. Ask an administrator to share a case.")
    def require_case(self, write=False):
        if not self.case_id:QMessageBox.information(self,"Create a case","Create an investigation first."); return False
        if write:
            role=self.store.user_case_role(self.case_id,self.current_user)
            if role not in {"owner","analyst"}:
                QMessageBox.warning(self,"Read-only access","Your case role does not allow changes.")
                return False
        return True
    def collect_tab(self):
        w=QWidget(); v=QVBoxLayout(w); intro=QLabel("Passive public-source collection. Select a target type and run a lookup."); intro.setObjectName("muted"); v.addWidget(intro)
        r=QHBoxLayout(); self.target_type=QComboBox(); self.target_type.addItems(["Domain","Public IP address","Website URL"]); self.target=QLineEdit(); self.target.setPlaceholderText("example.com"); r.addWidget(self.target_type); r.addWidget(self.target,1)
        self.collect_btn=QPushButton("Collect evidence"); self.collect_btn.setObjectName("primary"); self.collect_btn.clicked.connect(self.collect); r.addWidget(self.collect_btn); self.all_scan_btn=QPushButton("All-in-One scan"); self.all_scan_btn.clicked.connect(self.run_all_from_collect); r.addWidget(self.all_scan_btn); self.stop_collect_btn=QPushButton("Stop collector"); self.stop_collect_btn.setEnabled(False); self.stop_collect_btn.clicked.connect(self.stop_collect); r.addWidget(self.stop_collect_btn); v.addLayout(r)
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
        if not self.require_case(write=True): return
        item=Evidence(self.case_id,finding.get("source","Unknown"),finding.get("title","OSINT finding"),finding.get("url",""),finding.get("content",""),confidence=finding.get("confidence","Medium"),kind=finding.get("kind","Passive OSINT"))
        self.store.add_evidence(item)
        append_audit(APP_DIR/"audit.jsonl",{"action":"evidence_added","case_id":self.case_id,"evidence_id":item.id,"source":item.source,"title":item.title})
        self.refresh_evidence(); self.graph_panel.refresh(); self.status.setText("OSINT finding added to case")
    def evidence_tab(self):
        w=QWidget(); v=QVBoxLayout(w)
        filter_row=QHBoxLayout()
        self.timeline_from=QLineEdit(); self.timeline_from.setPlaceholderText("From YYYY-MM-DD (optional)")
        self.timeline_to=QLineEdit(); self.timeline_to.setPlaceholderText("To YYYY-MM-DD (optional)")
        self.timeline_query=QLineEdit(); self.timeline_query.setPlaceholderText("Search title, source, URL and evidence…")
        apply_filter=QPushButton("Apply filters"); apply_filter.clicked.connect(self.refresh_evidence)
        clear_filter=QPushButton("Clear"); clear_filter.clicked.connect(self.clear_timeline_filters)
        for control in (self.timeline_from,self.timeline_to,self.timeline_query,apply_filter,clear_filter):filter_row.addWidget(control)
        v.addLayout(filter_row)
        self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Observed UTC","Title","Source","Confidence","URL"])
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch); self.table.horizontalHeader().setSectionResizeMode(4,QHeaderView.ResizeMode.Stretch); self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.table.itemSelectionChanged.connect(self.show_evidence); v.addWidget(self.table,2)
        self.detail=QPlainTextEdit(); self.detail.setReadOnly(True); v.addWidget(self.detail,1)
        vault_group=QGroupBox("Evidence vault — encrypted payloads and attachments")
        vault_layout=QVBoxLayout(vault_group)
        self.vault_status_label=QLabel("Evidence payload encryption is not enabled.")
        self.vault_status_label.setWordWrap(True); vault_layout.addWidget(self.vault_status_label)
        vault_buttons=QHBoxLayout()
        enable=QPushButton("Encrypt evidence payloads"); enable.clicked.connect(self.enable_vault); vault_buttons.addWidget(enable)
        full_db=QPushButton("Enable full DB encryption"); full_db.clicked.connect(self.enable_database_encryption); vault_buttons.addWidget(full_db)
        capture_screen=QPushButton("Capture browser screenshot"); capture_screen.clicked.connect(self.capture_screenshot); vault_buttons.addWidget(capture_screen)
        exif=QPushButton("Inspect image / EXIF"); exif.clicked.connect(self.inspect_image_file); vault_buttons.addWidget(exif)
        compare=QPushButton("Compare two images"); compare.clicked.connect(self.compare_image_files); vault_buttons.addWidget(compare)
        reverse=QPushButton("Open reverse-image search"); reverse.clicked.connect(self.open_reverse_image_search); vault_buttons.addWidget(reverse)
        import_file=QPushButton("Import attachment"); import_file.clicked.connect(lambda:self.import_attachment("attachment")); vault_buttons.addWidget(import_file)
        import_image=QPushButton("Import screenshot"); import_image.clicked.connect(lambda:self.import_attachment("screenshot")); vault_buttons.addWidget(import_image)
        archive=QPushButton("Create WARC from file"); archive.clicked.connect(self.archive_as_warc); vault_buttons.addWidget(archive)
        capture=QPushButton("Capture public URL to WARC"); capture.clicked.connect(self.capture_url_warc); vault_buttons.addWidget(capture)
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
        signed=QPushButton("Export signed bundle"); signed.clicked.connect(self.export_signed_bundle); r.addWidget(signed)
        verify=QPushButton("Verify signed bundle"); verify.clicked.connect(self.verify_signed_bundle); r.addWidget(verify)
        v.addLayout(r); return w
    def refresh_cases(self):
        self.case_list.blockSignals(True); self.case_list.clear(); self.cases=self.store.cases_for_user(self.current_user)
        for c in self.cases:self.case_list.addItem(c["name"])
        self.case_list.blockSignals(False)
    def manage_team(self):
        if not self.current_user or self.current_user.get("role") != "admin":
            QMessageBox.warning(self, "Administrator only", "Only an administrator can manage local accounts.")
            return
        action, ok = QInputDialog.getItem(self, "Manage local accounts", "Action:",
                                          ["Create account", "Change account status"], 0, False)
        if not ok:
            return
        if action == "Change account status":
            users = [item for item in self.store.list_users() if item["id"] != self.current_user["id"]]
            if not users:
                QMessageBox.information(self, "No other accounts", "There are no other accounts to manage.")
                return
            labels = [item["username"] + " (" + item["role"] + ") · " +
                      ("disabled" if item["disabled"] else "active") for item in users]
            selected, ok = QInputDialog.getItem(self, "Account status", "Select account:", labels, 0, False)
            if not ok:
                return
            user = users[labels.index(selected)]
            enable = bool(user["disabled"])
            verb = "Enable" if enable else "Disable"
            answer = QMessageBox.question(self, verb + " account",
                verb + " " + user["username"] + "? This affects the next sign-in.")
            if answer != QMessageBox.StandardButton.Yes:
                return
            try:
                self.store.set_user_disabled(user["id"], not enable)
                QMessageBox.information(self, "Account updated",
                    user["username"] + " is now " + ("active" if enable else "disabled") + ".")
            except Exception as exc:
                QMessageBox.warning(self, "Account not changed", str(exc))
            return
        username, ok = QInputDialog.getText(self, "Create local account", "Username:")
        if not ok or not username.strip():
            return
        password, ok = QInputDialog.getText(self, "Create local account", "Password (12+ characters):",
                                             QLineEdit.EchoMode.Password)
        if not ok:
            return
        role, ok = QInputDialog.getItem(self, "Account role", "Role:", ["analyst", "viewer"], 0, False)
        if not ok:
            return
        try:
            user_id = self.store.create_user(username.strip(), password, role)
            if self.case_id:
                answer = QMessageBox.question(self, "Share active case",
                    "Assign this new account to the active case as well?")
                if answer == QMessageBox.StandardButton.Yes:
                    self.store.add_case_member(self.case_id, user_id, role)
            QMessageBox.information(self, "Account created",
                "Local account created. Share individual cases using the Share active case control.")
        except Exception as exc:
            QMessageBox.warning(self, "Account not created", str(exc))

    def share_case(self):
        if not self.require_case(write=True):
            return
        if not self.current_user or self.current_user.get("role") != "admin":
            role = self.store.user_case_role(self.case_id, self.current_user)
            if role != "owner":
                QMessageBox.warning(self, "Permission denied", "Only a case owner or administrator can share this case.")
                return
        users = self.store.list_users()
        members = {item["id"] for item in self.store.case_members(self.case_id)}
        candidates = [item for item in users if not item["disabled"] and item["id"] not in members]
        if not candidates:
            QMessageBox.information(self, "No available accounts", "Create another account or remove an existing membership first.")
            return
        labels = [item["username"] + " (" + item["role"] + ")" for item in candidates]
        selected, ok = QInputDialog.getItem(self, "Share active case", "Account:", labels, 0, False)
        if not ok:
            return
        member = candidates[labels.index(selected)]
        role, ok = QInputDialog.getItem(self, "Case role", "Grant role:", ["analyst", "viewer"], 0, False)
        if not ok:
            return
        try:
            self.store.add_case_member(self.case_id, member["id"], role)
            append_audit(APP_DIR/"audit.jsonl", {"action":"case_shared","case_id":self.case_id,
                "user_id":member["id"],"role":role,"shared_by":self.current_user["id"]})
            QMessageBox.information(self, "Case shared", member["username"] + " now has " + role + " access.")
            self.refresh_cases()
        except Exception as exc:
            QMessageBox.warning(self, "Sharing failed", str(exc))

    def monitoring_evidence_added(self, case_id):
        if case_id == self.case_id:
            self.refresh_evidence()
            self.graph_panel.refresh()
            self.status.setText("Scheduled passive monitor added case evidence.")

    def new_case(self):
        name,ok=QInputDialog.getText(self,"New investigation","Case name:")
        if ok and name.strip():
            if not self.current_user or self.current_user.get("role")=="viewer":
                QMessageBox.warning(self,"Permission denied","Only analysts and administrators can create cases."); return
            cid=self.store.create_case(name.strip(),owner_id=self.current_user["id"]); append_audit(APP_DIR/"audit.jsonl",{"action":"case_created","case_id":cid,"name":name.strip(),"created_by":self.current_user["id"]}); self.refresh_cases()
            self.case_list.setCurrentRow(next(i for i,c in enumerate(self.cases) if c["id"]==cid))
    def case_selected(self,i):
        if i<0 or i>=len(getattr(self,"cases",[])):return
        self.case_id=self.cases[i]["id"]
        role=self.store.user_case_role(self.case_id,self.current_user) or "viewer"
        self.case_label.setText("ACTIVE CASE · "+role.upper())
        writable=role in {"owner","analyst"}
        self.collect_btn.setEnabled(writable); self.all_scan_btn.setEnabled(writable)
        self.integrations.all_button.setEnabled(writable); self.integrations.run_button.setEnabled(writable); self.integrations.identity_button.setEnabled(writable)
        self.graph_panel.add_lead_button.setEnabled(writable); self.graph_panel.merge_button.setEnabled(writable); self.graph_panel.undo_button.setEnabled(writable)
        self.new_case_button.setEnabled(bool(self.current_user and self.current_user.get("role") in {"admin","analyst"}))
        self.refresh_evidence(); self.refresh_attachments(); self.graph_panel.set_case(self.case_id); self.monitoring_panel.set_case(self.case_id); self.content_monitor_panel.set_case(self.case_id)
    def collect(self):
        if not self.require_case(write=True):return
        value=self.target.text().strip()
        if not value:return
        selection=self.target_type.currentText()
        fn={"Domain":collect_domain,"Public IP address":collect_ip,"Website URL":collect_website}[selection]
        target_type={"Domain":"domain","Public IP address":"ip","Website URL":"url"}[selection]
        registry=CollectorRegistry()
        registry.register(CollectorSpec("single_passive_collection",
            run=lambda target, context: fn(target), mode="passive", target_types=(target_type,)))
        self.collect_cancellation=CancellationToken()
        self.collect_btn.setEnabled(False); self.stop_collect_btn.setEnabled(True); self.status.setText("Collecting in an isolated process…")
        self.worker=Worker(lambda: run_workflow(value,registry,target_type=target_type,
            policy=ExecutionPolicy(max_workers=1,timeout_seconds=60.0,allow_active=False),
            cancellation=self.collect_cancellation))
        self.worker.done.connect(self.collection_done); self.worker.failed.connect(self.failed)
        self.worker.finished.connect(lambda:(self.collect_btn.setEnabled(True),self.stop_collect_btn.setEnabled(False)))
        self.worker.start()

    def stop_collect(self):
        token=getattr(self,"collect_cancellation",None)
        if token:
            token.cancel()
            self.status.setText("Stop requested; collector process is being terminated…")

    def collection_done(self,result):
        if not self.require_case(write=True):return
        findings=result.get("findings",[]) if isinstance(result,dict) else []
        for finding in findings:
            source=finding.get("source","Passive collection")
            title=finding.get("title","OSINT finding")
            url=finding.get("url","")
            content=finding.get("content","")
            confidence=finding.get("confidence","Low")
            item=Evidence(self.case_id,source,title,url,content,confidence=confidence,kind=finding.get("kind","OSINT finding"))
            self.store.add_evidence(item); append_audit(APP_DIR/"audit.jsonl",{"action":"evidence_added","case_id":self.case_id,"evidence_id":item.id,"source":item.source,"title":item.title})
            self.collect_log.appendPlainText(f"\n[{confidence}] {title}\nSource: {source}\nURL: {url}\n{content[:4500]}")
        self.status.setText("Workflow "+result.get("status","completed")+" · "+str(len(findings))+" findings")
        self.refresh_evidence(); self.graph_panel.refresh()
    def failed(self,msg):self.status.setText("Task failed"); QMessageBox.warning(self,"Task failed",msg)
    def refresh_evidence(self):
        if not self.case_id:return
        self.evidence=self.store.evidence(self.case_id)
        start=self.timeline_from.text().strip() if hasattr(self,"timeline_from") else ""
        end=self.timeline_to.text().strip() if hasattr(self,"timeline_to") else ""
        query=self.timeline_query.text().strip().casefold() if hasattr(self,"timeline_query") else ""
        from datetime import datetime
        for label, value in (("From", start), ("To", end)):
            if value:
                try:
                    datetime.strptime(value, "%Y-%m-%d")
                except ValueError:
                    QMessageBox.warning(self, "Invalid timeline date",
                        label + " date must use YYYY-MM-DD format.")
                    return
        if start and end and start > end:
            QMessageBox.warning(self, "Invalid timeline range",
                "The start date must not be later than the end date.")
            return
        self.visible_evidence=[]
        for item in self.evidence:
            day=(item.observed_at or "")[:10]
            if start and day and day < start: continue
            if end and day and day > end: continue
            haystack=" ".join((item.title,item.source,item.url,item.content)).casefold()
            if query and query not in haystack: continue
            self.visible_evidence.append(item)
        self.table.setRowCount(len(self.visible_evidence))
        for i,e in enumerate(self.visible_evidence):
            for j,val in enumerate([e.observed_at[:19].replace("T"," "),e.title,e.source,e.confidence,e.url]):self.table.setItem(i,j,QTableWidgetItem(val))
        if hasattr(self,"status"):
            self.status.setText(f"Timeline: {len(self.visible_evidence)} of {len(self.evidence)} evidence records")
    def clear_timeline_filters(self):
        self.timeline_from.clear(); self.timeline_to.clear(); self.timeline_query.clear(); self.refresh_evidence()

    def enable_database_encryption(self):
        if not self.require_case(write=True): return
        answer=QMessageBox.question(self,"Encrypt complete case database",
            "Convert the entire SQLite database to SQLCipher AES-256 page encryption? A plaintext backup will be retained beside the database. Keep your OS keyring available; loss of the key makes the encrypted database unreadable.")
        if answer != QMessageBox.StandardButton.Yes:return
        try:
            result=self.store.enable_database_encryption()
            QMessageBox.information(self,"Database encrypted",
                "Full SQLCipher encryption is enabled.\nPlaintext backup: "+result["plaintext_backup"]+
                "\nThe original is encrypted. Store the backup securely or delete it after validating your recovery plan.")
            self.status.setText("Full database encryption enabled")
        except Exception as exc:
            QMessageBox.critical(self,"Database encryption unavailable",str(exc))

    def capture_screenshot(self):
        if not self.require_case(write=True):return
        status=self.store.vault_status()
        if not status.get("enabled") or status.get("locked"):
            QMessageBox.information(self,"Encrypted vault required","Enable and unlock the evidence vault before capturing a screenshot.")
            return
        url,ok=QInputDialog.getText(self,"Capture public webpage","Public HTTP(S) page URL:")
        if not ok or not url.strip():return
        handle=tempfile.NamedTemporaryFile(prefix="smartintel-shot-",suffix=".png",delete=False)
        self.screenshot_temp=Path(handle.name); handle.close()
        self.status.setText("Capturing public browser screenshot…")
        self.worker=Worker(lambda: capture_public_screenshot(url.strip(),self.screenshot_temp,full_page=True))
        self.worker.done.connect(self.screenshot_done)
        self.worker.failed.connect(self.screenshot_failed)
        self.worker.start()

    def screenshot_done(self,details):
        try:
            row=self.store.add_attachment(self.case_id,details["path"],kind="screenshot")
            append_audit(APP_DIR/"audit.jsonl",{"action":"browser_screenshot_captured","case_id":self.case_id,
                "attachment_id":row["id"],"url":details["url"],"sha256":row["sha256"]})
            self.refresh_attachments()
            self.status.setText("Screenshot captured and encrypted in the evidence vault")
            QMessageBox.information(self,"Screenshot saved",
                "Browser screenshot stored as an encrypted attachment.\nURL: "+details["url"]+
                "\nHTTP status: "+str(details["status_code"])+"\nSHA-256: "+row["sha256"])
        except Exception as exc:
            QMessageBox.critical(self,"Screenshot storage failed",str(exc))
        finally:
            if getattr(self,"screenshot_temp",None):self.screenshot_temp.unlink(missing_ok=True)

    def screenshot_failed(self,message):
        if getattr(self,"screenshot_temp",None):self.screenshot_temp.unlink(missing_ok=True)
        self.failed(message)

    def inspect_image_file(self):
        if not self.require_case(write=True):return
        path,_=QFileDialog.getOpenFileName(self,"Inspect local image","",
            "Images (*.jpg *.jpeg *.png *.webp *.tif *.tiff *.bmp)")
        if not path:return
        try:
            details=inspect_image(path)
            from .models import Evidence
            payload=json.dumps(details,ensure_ascii=False,indent=2)
            if details.get("gps"):
                answer=QMessageBox.question(self,"Location metadata found",
                    "This image contains GPS metadata. Add its location details to the current case evidence?")
                if answer != QMessageBox.StandardButton.Yes:return
            item=Evidence(self.case_id,"Local image metadata",details["filename"],content=payload,
                          confidence="Medium",kind="Image metadata")
            self.store.add_evidence(item)
            self.refresh_evidence(); self.graph_panel.refresh()
            QMessageBox.information(self,"Image analysis",
                "Local EXIF and image hash analysis saved.\nDimensions: "+str(details["width"])+" × "+str(details["height"])+
                "\nSHA-256: "+details["sha256"]+"\ndHash64: "+details["dhash64"]+
                "\nGPS fields: "+str(len(details.get("gps",{})))+
                "\nUse the reverse-image search button to open a provider manually; the file was not uploaded.")
        except Exception as exc:QMessageBox.warning(self,"Image inspection failed",str(exc))

    def compare_image_files(self):
        if not self.require_case(write=True):return
        first,_=QFileDialog.getOpenFileName(self,"Choose first image","",
            "Images (*.jpg *.jpeg *.png *.webp *.tif *.tiff *.bmp)")
        if not first:return
        second,_=QFileDialog.getOpenFileName(self,"Choose second image","",
            "Images (*.jpg *.jpeg *.png *.webp *.tif *.tiff *.bmp)")
        if not second:return
        try:
            result=compare_images(first,second)
            from .models import Evidence
            item=Evidence(self.case_id,"Local image comparison",
                result["left"]+" vs "+result["right"],content=json.dumps(result,ensure_ascii=False,indent=2),
                confidence="Low",kind="Perceptual image comparison")
            self.store.add_evidence(item)
            self.refresh_evidence()
            QMessageBox.information(self,"Image comparison",
                "dHash Hamming distance: "+str(result["hamming_distance"])+"/64"+
                "\nSimilarity indicator: "+str(result["similarity_percent"])+"%"+
                "\nThis is a rough visual resemblance clue, not proof of the same photo or subject.")
        except Exception as exc:
            QMessageBox.warning(self,"Image comparison failed",str(exc))

    def open_reverse_image_search(self):
        from .image_intel import inspect_image
        path,_=QFileDialog.getOpenFileName(self,"Choose image for reverse search","",
            "Images (*.jpg *.jpeg *.png *.webp *.tif *.tiff *.bmp)")
        if not path:return
        try:
            details=inspect_image(path)
            names=["Google Lens","Bing Visual Search","TinEye"]
            urls={row["provider"]:row["url"] for row in details["reverse_search_options"]}
            provider,ok=QInputDialog.getItem(self,"Reverse image search",
                "Choose a provider. Smart Intel will open the site only; you decide whether to upload the image.",names,0,False)
            if ok and provider:QDesktopServices.openUrl(QUrl(urls[provider]))
        except Exception as exc:QMessageBox.warning(self,"Reverse search unavailable",str(exc))

    def export_signed_bundle(self):
        if not self.require_case():return
        case=next((c for c in self.store.cases() if c["id"]==self.case_id),{"name":"Smart Intel case"})
        items=[{"id":e.id,"title":e.title,"source":e.source,"url":e.url,"content":e.content,
                "observed_at":e.observed_at,"confidence":e.confidence,"kind":e.kind}
               for e in self.store.evidence(self.case_id)]
        attachments=[]
        for row in self.store.attachments(self.case_id):
            attachments.append({"id":row["id"],"filename":row["filename"],"kind":row["kind"],
                                "content":self.store.read_attachment(row["id"])})
        path,_=QFileDialog.getSaveFileName(self,"Export signed evidence bundle","smart-intel-signed.zip","ZIP (*.zip)")
        if not path:return
        tsa_url,ok=QInputDialog.getText(self,"Optional trusted timestamp","RFC 3161 TSA URL (leave blank to skip):")
        if not ok:return
        tsa_ca=""
        if tsa_url.strip():
            tsa_ca,_=QFileDialog.getOpenFileName(self,"Optional TSA trust CA file")
        try:
            result=signed_export(case,items,path,attachments=attachments,tsa_url=tsa_url.strip(),tsa_ca_file=tsa_ca)
            QMessageBox.information(self,"Signed export created",
                "Ed25519 signature created.\nBundle SHA-256: "+result["sha256"]+
                "\nManifest SHA-256: "+result["manifest_sha256"]+
                "\nIncluded attachments: "+str(len(attachments))+
                "\nTimestamp status: "+result["timestamp_status"]+
                "\nSigning-key SHA-256 fingerprint: "+result["public_key_sha256"]+
                "\nFor authenticity, compare the fingerprint with a separately trusted copy.")
        except Exception as exc:QMessageBox.critical(self,"Signed export failed",str(exc))

    def verify_signed_bundle(self):
        path,_=QFileDialog.getOpenFileName(self,"Verify signed evidence bundle","","ZIP (*.zip)")
        if not path:return
        ca_file,_=QFileDialog.getOpenFileName(self,"Optional TSA trust CA certificate (cancel to skip)")
        try:
            result=verify_signed_export(path,tsa_ca_file=ca_file)
            if result["valid"]:
                QMessageBox.information(self,"Signature verifies",
                    "The Ed25519 signature and manifest hash verify.\nManifest SHA-256: "+result["sha256"]+
                    "\nPublic-key SHA-256 fingerprint: "+result["public_key_sha256"]+
                    "\nRFC 3161 timestamp: "+result["timestamp_status"]+
                    "\nAuthenticate the signer fingerprint independently before trusting authorship.")
            else:
                QMessageBox.warning(self,"Signature invalid","The bundle signature or manifest hash does not match.")
        except Exception as exc:QMessageBox.critical(self,"Verification failed",str(exc))

    def show_evidence(self):
        rows=self.table.selectionModel().selectedRows()
        if rows:
            e=self.visible_evidence[rows[0].row()]; self.detail.setPlainText(f"{e.title}\nSource: {e.source}\nURL: {e.url}\nObserved: {e.observed_at}\nConfidence: {e.confidence}\n\n{e.content}")
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
        state = "Vault is locked: OS credential-store key unavailable. Do not reset the key." if status.get("locked") else ("Encrypted evidence payloads are enabled. " if status["enabled"] else "Encryption is not enabled. ")
        self.vault_status_label.setText(state + status["scope"])
    def enable_vault(self):
        if QMessageBox.question(self,"Enable evidence encryption","Create/use an encryption key in the operating-system credential store and encrypt all existing evidence content? Keep your OS credential-store access: losing the key means losing access to encrypted evidence.") != QMessageBox.StandardButton.Yes: return
        try:
            self.store.enable_evidence_encryption()
            self.refresh_evidence(); self.refresh_attachments()
            QMessageBox.information(self,"Vault enabled","Evidence content is now encrypted at rest. Case names and other SQLite metadata remain plaintext.")
        except Exception as exc: QMessageBox.critical(self,"Vault error",str(exc))
    def import_attachment(self,kind):
        if not self.require_case(write=True): return
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
        if not self.require_case(write=True): return
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
    def capture_url_warc(self):
        if not self.require_case(write=True): return
        url,ok=QInputDialog.getText(self,"Capture public URL","HTTP or HTTPS URL (one response; redirects are not followed):")
        if not ok or not url.strip(): return
        try:
            if not self.store.vault_status()["enabled"]:
                QMessageBox.information(self,"Enable encryption","Enable evidence encryption before creating WARC records."); return
            record=make_warc_response(url.strip())
            with tempfile.NamedTemporaryFile(prefix="smartintel-response-",suffix=".warc",delete=False) as handle:
                handle.write(record); temp_path=Path(handle.name)
            try: row=self.store.add_attachment(self.case_id,temp_path,kind="warc_response")
            finally: temp_path.unlink(missing_ok=True)
            append_audit(APP_DIR/"audit.jsonl",{"action":"url_warc_captured","case_id":self.case_id,"attachment_id":row["id"],"url":url.strip(),"sha256":row["sha256"]})
            self.refresh_attachments(); self.status.setText("Public HTTP response captured to encrypted WARC")
        except Exception as exc: QMessageBox.critical(self,"WARC capture failed",str(exc))
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

def _authenticate_desktop_user(store):
    if store.users_count() == 0:
        username, ok = QInputDialog.getText(None, "First-run administrator setup",
                                             "Create the first administrator username:")
        if not ok or not username.strip():
            return None
        password, ok = QInputDialog.getText(None, "First-run administrator setup",
                                             "Administrator password (at least 12 characters):",
                                             QLineEdit.EchoMode.Password)
        if not ok:
            return None
        try:
            user_id = store.create_user(username.strip(), password, "admin")
            return {"id": user_id, "username": username.strip(), "role": "admin"}
        except Exception as exc:
            QMessageBox.critical(None, "Account setup failed", str(exc))
            return None

    while True:
        username, ok = QInputDialog.getText(None, "Smart Intel sign in", "Username:")
        if not ok:
            return None
        password, ok = QInputDialog.getText(None, "Smart Intel sign in", "Password:",
                                             QLineEdit.EchoMode.Password)
        if not ok:
            return None
        user = store.authenticate_user(username, password)
        if user:
            return user
        QMessageBox.warning(None, "Sign in failed", "Invalid username or password, or the account is disabled.")


def main():
    app=QApplication(sys.argv)
    app.setApplicationName("Smart Intel")
    app.setStyleSheet(STYLE)
    try:
        store=Store()
        user=_authenticate_desktop_user(store)
        if not user:
            return
        window=MainWindow(user)
        window.show()
        sys.exit(app.exec())
    except Exception as exc:
        QMessageBox.critical(None, "Smart Intel startup failed", str(exc))
        raise
