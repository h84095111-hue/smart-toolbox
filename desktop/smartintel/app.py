import sys, html
from pathlib import Path
from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import *
from .storage import Store
from .models import Evidence
from .collectors.passive import collect_domain, collect_ip, collect_website
from .providers.ai import analyze, save_api_key, get_api_key, delete_api_key

STYLE="""QWidget{background:#0b1220;color:#e6edf8;font-family:Segoe UI,Arial;font-size:13px}
QFrame#sidebar{background:#101a2c;border-right:1px solid #283852}
QLabel#brand{font-size:22px;font-weight:800;padding:10px;color:#fff}
QLabel#muted{color:#94a4bd} QLabel#heading{font-size:25px;font-weight:800;color:#fff}
QLabel#eyebrow{color:#9d91ff;font-size:11px;font-weight:800;letter-spacing:2px}
QPushButton{background:#1c2a42;border:1px solid #334661;border-radius:8px;padding:10px;text-align:left}
QPushButton:hover{background:#283958;border-color:#8176ff}
QPushButton#primary{background:#6558df;border:1px solid #897fff;color:#fff;font-weight:700}
QLineEdit,QTextEdit,QPlainTextEdit,QComboBox,QListWidget{background:#0e192b;border:1px solid #30415e;border-radius:7px;padding:9px}
QTableWidget{background:#0e192b;border:1px solid #30415e;gridline-color:#273750}
QHeaderView::section{background:#18263d;color:#aebbd0;padding:8px;border:0}
QTabBar::tab{background:#142138;padding:10px 16px} QTabBar::tab:selected{background:#5148a6}"""

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
        for p in ("OpenAI","Gemini","Claude"):
            v.addWidget(QLabel(p+" API key")); row=QHBoxLayout(); e=QLineEdit(); e.setEchoMode(QLineEdit.EchoMode.Password); e.setText(get_api_key(p) or ""); row.addWidget(e)
            clear=QPushButton("Clear"); clear.clicked.connect(lambda _,provider=p,field=e:self.clear(provider,field)); row.addWidget(clear); v.addLayout(row); self.fields[p]=e
        note=QLabel("Provider usage is billed separately by each AI provider."); note.setObjectName("muted"); v.addWidget(note)
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
        for text,idx in [("⌕  Collect intelligence",0),("◉  Evidence & timeline",1),("⌘  AI analyst",2),("▤  Reports",3)]:
            b=QPushButton(text); b.clicked.connect(lambda _,i=idx:self.tabs.setCurrentIndex(i)); sv.addWidget(b)
        settings=QPushButton("⚙  AI provider settings"); settings.clicked.connect(lambda:SettingsDialog(self).exec()); sv.addWidget(settings)
        privacy=QLabel("● PASSIVE PUBLIC-SOURCE MODE\nNo login attempts · No exploitation\nEvidence stored locally"); privacy.setStyleSheet("color:#8fe0bd;background:#142b30;border:1px solid #28534f;border-radius:8px;padding:12px;font-size:11px"); sv.addWidget(privacy)
        row.addWidget(side)
        main=QWidget(); mv=QVBoxLayout(main); mv.setContentsMargins(25,20,25,18)
        top=QHBoxLayout(); eyebrow=QLabel("INTELLIGENCE WORKSPACE"); eyebrow.setObjectName("eyebrow"); top.addWidget(eyebrow); top.addStretch()
        self.status=QLabel("Ready"); self.status.setObjectName("muted"); top.addWidget(self.status); mv.addLayout(top)
        hero=QLabel("Investigate the public web.\nConnect evidence. Find the signal."); hero.setObjectName("heading"); hero.setStyleSheet("background:#182449;border:1px solid #38457a;border-radius:12px;padding:18px"); mv.addWidget(hero)
        self.tabs=QTabWidget(); self.tabs.addTab(self.collect_tab(),"Collect"); self.tabs.addTab(self.evidence_tab(),"Evidence & Timeline"); self.tabs.addTab(self.ai_tab(),"AI Analyst"); self.tabs.addTab(self.report_tab(),"Reports"); mv.addWidget(self.tabs,1)
        row.addWidget(main,1); self.setCentralWidget(root); self.refresh_cases()
        if self.case_list.count():self.case_list.setCurrentRow(0)
        else:self.new_case()
    def require_case(self):
        if not self.case_id:QMessageBox.information(self,"Create a case","Create an investigation first."); return False
        return True
    def collect_tab(self):
        w=QWidget(); v=QVBoxLayout(w); intro=QLabel("Passive public-source collection. Select a target type and run a lookup."); intro.setObjectName("muted"); v.addWidget(intro)
        r=QHBoxLayout(); self.target_type=QComboBox(); self.target_type.addItems(["Domain","Public IP address","Website URL"]); self.target=QLineEdit(); self.target.setPlaceholderText("example.com"); r.addWidget(self.target_type); r.addWidget(self.target,1)
        self.collect_btn=QPushButton("Collect evidence"); self.collect_btn.setObjectName("primary"); self.collect_btn.clicked.connect(self.collect); r.addWidget(self.collect_btn); v.addLayout(r)
        self.collect_log=QPlainTextEdit(); self.collect_log.setReadOnly(True); self.collect_log.setPlaceholderText("Collection output appears here…"); v.addWidget(self.collect_log,1)
        hint=QLabel("DNS · RDAP · TLS certificate · public website metadata, headers and links. No active scanning."); hint.setObjectName("muted"); v.addWidget(hint); return w
    def evidence_tab(self):
        w=QWidget(); v=QVBoxLayout(w); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Observed UTC","Title","Source","Confidence","URL"])
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch); self.table.horizontalHeader().setSectionResizeMode(4,QHeaderView.ResizeMode.Stretch); self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.table.itemSelectionChanged.connect(self.show_evidence); v.addWidget(self.table,2)
        self.detail=QPlainTextEdit(); self.detail.setReadOnly(True); v.addWidget(self.detail,1); return w
    def ai_tab(self):
        w=QWidget(); v=QVBoxLayout(w); note=QLabel("Analyze evidence already collected in this case. The assistant is instructed to separate facts, inferences and unknowns."); note.setWordWrap(True); note.setObjectName("muted"); v.addWidget(note)
        r=QHBoxLayout(); self.provider=QComboBox(); self.provider.addItems(["OpenAI","Gemini","Claude"]); r.addWidget(QLabel("Provider")); r.addWidget(self.provider); r.addStretch(); v.addLayout(r)
        self.prompt=QLineEdit(); self.prompt.setPlaceholderText("Summarize evidence and identify gaps…"); v.addWidget(self.prompt)
        b=QPushButton("Analyze collected evidence"); b.setObjectName("primary"); b.clicked.connect(self.run_ai); v.addWidget(b)
        self.ai_result=QPlainTextEdit(); self.ai_result.setReadOnly(True); v.addWidget(self.ai_result,1); return w
    def report_tab(self):
        w=QWidget(); v=QVBoxLayout(w); self.preview=QTextBrowser(); v.addWidget(self.preview,1)
        r=QHBoxLayout(); b=QPushButton("Preview report"); b.clicked.connect(lambda:self.preview.setHtml(self.report_html())); r.addWidget(b)
        export=QPushButton("Export HTML report"); export.setObjectName("primary"); export.clicked.connect(self.export_report); r.addWidget(export); v.addLayout(r); return w
    def refresh_cases(self):
        self.case_list.blockSignals(True); self.case_list.clear(); self.cases=self.store.cases()
        for c in self.cases:self.case_list.addItem(c["name"])
        self.case_list.blockSignals(False)
    def new_case(self):
        name,ok=QInputDialog.getText(self,"New investigation","Case name:")
        if ok and name.strip():
            cid=self.store.create_case(name.strip()); self.refresh_cases()
            self.case_list.setCurrentRow(next(i for i,c in enumerate(self.cases) if c["id"]==cid))
    def case_selected(self,i):
        if i<0 or i>=len(getattr(self,"cases",[])):return
        self.case_id=self.cases[i]["id"]; self.case_label.setText("ACTIVE CASE"); self.refresh_evidence()
    def collect(self):
        if not self.require_case():return
        value=self.target.text().strip()
        if not value:return
        fn={"Domain":collect_domain,"Public IP address":collect_ip,"Website URL":collect_website}[self.target_type.currentText()]
        self.collect_btn.setEnabled(False); self.status.setText("Collecting…")
        self.worker=Worker(fn,value); self.worker.done.connect(self.collection_done); self.worker.failed.connect(self.failed); self.worker.finished.connect(lambda:self.collect_btn.setEnabled(True)); self.worker.start()
    def collection_done(self,findings):
        for f in findings:
            self.store.add_evidence(Evidence(self.case_id,f.source,f.title,f.url,f.value,confidence=f.confidence,kind="OSINT finding"))
            self.collect_log.appendPlainText(f"\n[{f.confidence}] {f.title}\nSource: {f.source}\nURL: {f.url}\n{f.value[:4500]}")
        self.status.setText(f"Collected {len(findings)} findings"); self.refresh_evidence()
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
    def export_report(self):
        data=self.report_html()
        if not data:return
        path,_=QFileDialog.getSaveFileName(self,"Export report","smart-intel-report.html","HTML (*.html)")
        if path:Path(path).write_text(data,encoding="utf-8"); QMessageBox.information(self,"Exported","Report saved.")

def main():
    app=QApplication(sys.argv); app.setApplicationName("Smart Intel"); app.setStyleSheet(STYLE); window=MainWindow(); window.show(); sys.exit(app.exec())
