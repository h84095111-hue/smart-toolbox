"""PyQt6 evidence graph and analyst panel."""
from __future__ import annotations
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QPen, QColor, QFont
from PyQt6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,
    QGraphicsView,QGraphicsScene,QGraphicsEllipseItem,QGraphicsSimpleTextItem,QGraphicsLineItem,
    QTextBrowser,QSplitter,QMessageBox,QFrame)
from .identity_graph import build_identity_graph, validate_graph
from .match_scoring import assess_false_positive_risk
from .ai_analysis import analyze_evidence

class _AnalystTask(QThread):
    done=pyqtSignal(str); failed=pyqtSignal(str)
    def __init__(self,question,graph,risk,provider,evidence):
        super().__init__(); self.args=(question,graph,risk,provider,evidence)
    def run(self):
        try:self.done.emit(analyze_evidence(*self.args))
        except Exception as exc:self.failed.emit(str(exc))

class _NodeItem(QGraphicsEllipseItem):
    def __init__(self,node,x,y,callback):
        super().__init__(-42,-24,84,48); self.node=node; self.callback=callback
        colors={"source":"#34445f","email":"#286b66","phone":"#75532c","username":"#51458a","profile_or_url":"#315b83"}
        self.setBrush(QBrush(QColor(colors.get(node.kind,"#45536c"))))
        self.setPen(QPen(QColor("#a8b7d1"),1.4)); self.setPos(x,y); self.setZValue(2)
        self.setToolTip(node.kind+" · "+node.label)
        label=QGraphicsSimpleTextItem(node.label[:17],self); label.setBrush(QBrush(QColor("#ffffff")))
        label.setFont(QFont("Segoe UI",8)); rect=label.boundingRect(); label.setPos(-rect.width()/2,-rect.height()/2)
    def mousePressEvent(self,event):
        self.callback(self.node); super().mousePressEvent(event)

class IdentityGraphPanel(QWidget):
    def __init__(self,store,parent=None):
        super().__init__(parent); self.store=store; self.case_id=None; self.graph=None; self.evidence=[]
        self.task=None; self.selected=None
        root=QVBoxLayout(self); root.setContentsMargins(8,8,8,8)
        header=QHBoxLayout(); title=QLabel("Evidence relationship graph"); title.setStyleSheet("font-size:19px;font-weight:800")
        header.addWidget(title); header.addStretch()
        self.refresh_btn=QPushButton("Refresh graph"); self.refresh_btn.clicked.connect(self.refresh); header.addWidget(self.refresh_btn)
        root.addLayout(header)
        note=QLabel("Nodes are extracted identifiers and source records. Lines mean “observed in this evidence”, not confirmed identity.")
        note.setWordWrap(True); note.setStyleSheet("color:#91a2bd"); root.addWidget(note)
        split=QSplitter(Qt.Orientation.Horizontal)
        self.scene=QGraphicsScene(self); self.view=QGraphicsView(self.scene); self.view.setRenderHint(self.view.renderHints())
        self.view.setMinimumHeight(360); self.view.setStyleSheet("background:#091323;border:1px solid #263650;border-radius:8px")
        split.addWidget(self.view)
        side=QWidget(); sv=QVBoxLayout(side); self.detail=QTextBrowser(); self.detail.setMinimumWidth(270); sv.addWidget(self.detail,1)
        self.risk=QLabel("False-positive risk index: —"); self.risk.setWordWrap(True); self.risk.setStyleSheet("font-weight:800;padding:8px;background:#17243a;border-radius:7px"); sv.addWidget(self.risk)
        row=QHBoxLayout(); self.provider=QComboBox(); self.provider.addItems(["Ollama","OpenAI","Gemini","Claude"]); row.addWidget(self.provider)
        self.analyze_btn=QPushButton("Analyze graph with AI"); self.analyze_btn.clicked.connect(self.run_analysis); row.addWidget(self.analyze_btn); sv.addLayout(row)
        self.analysis=QTextBrowser(); self.analysis.setPlaceholderText("AI analysis will appear here. Ollama runs locally; cloud providers require configured keys."); sv.addWidget(self.analysis,2)
        split.addWidget(side); split.setSizes([700,360]); root.addWidget(split,1)
        self.status=QLabel("Select a case and refresh to build its graph."); self.status.setStyleSheet("color:#91a2bd"); root.addWidget(self.status)
    def set_case(self,case_id):
        self.case_id=case_id; self.selected=None; self.refresh()
    def refresh(self):
        if not self.case_id: return
        self.evidence=self.store.evidence(self.case_id)
        self.graph=build_identity_graph(self.evidence); validate_graph(self.graph)
        self.scene.clear(); self.selected=None
        nodes=self.graph.nodes; count=len(nodes)
        if not nodes:
            self.detail.setPlainText("No evidence is available in this case yet. Add evidence, then refresh the graph.")
            self.risk.setText("False-positive risk index: —"); self.status.setText("No graph nodes."); return
        import math
        positions={}
        radius=max(125, min(260, count*13))
        for i,node in enumerate(nodes):
            angle=(2*math.pi*i/max(1,count))-math.pi/2
            positions[node.id]=(radius*math.cos(angle),radius*math.sin(angle))
        for edge in self.graph.edges:
            x1,y1=positions[edge.source]; x2,y2=positions[edge.target]
            line=QGraphicsLineItem(x1,y1,x2,y2); line.setPen(QPen(QColor("#60718e"),1.2)); line.setZValue(0); self.scene.addItem(line)
        for node in nodes:
            x,y=positions[node.id]; item=_NodeItem(node,x,y,self.select_node); self.scene.addItem(item)
        self.scene.setSceneRect(-radius-100,-radius-100,radius*2+200,radius*2+200)
        self.view.fitInView(self.scene.sceneRect(),Qt.AspectRatioMode.KeepAspectRatio)
        self.status.setText(f"{len(nodes)} nodes · {len(self.graph.edges)} evidence links · {len(self.evidence)} evidence records")
        self.detail.setPlainText("Click a node to inspect its supporting evidence.")
    def select_node(self,node):
        self.selected=node
        related=[e for e in self.evidence if e.id in node.evidence_ids]
        sources={e.source for e in related}
        risk=assess_false_positive_risk(independent_sources=max(0,len(sources)-1))
        self.risk.setText(f"False-positive risk index: {risk.score}/100 ({risk.risk_band.upper()})\nUncalibrated heuristic — not a probability.")
        lines=[f"{node.kind.upper()}: {node.label}",f"Supporting evidence records: {len(related)}",""]
        for e in related:
            lines.extend([f"• {e.title}",f"  Source: {e.source}",f"  Evidence ID: {e.id}",f"  URL: {e.url or 'Not supplied'}",""])
        self.detail.setPlainText("\n".join(lines))
    def run_analysis(self):
        if not self.graph or not self.evidence:
            QMessageBox.information(self,"No graph","Collect or add evidence to this case first."); return
        risk=(assess_false_positive_risk(independent_sources=max(0,len({e.source for e in self.evidence})-1))).to_dict()
        question="Analyze this case graph. Identify supported connections, weak leads, contradictions and safe next steps."
        self.analyze_btn.setEnabled(False); self.status.setText("AI analysis running…")
        self.task=_AnalystTask(question,self.graph.to_dict(),risk,self.provider.currentText(),self.evidence)
        self.task.done.connect(self.analysis_done); self.task.failed.connect(self.analysis_failed)
        self.task.finished.connect(lambda:self.analyze_btn.setEnabled(True)); self.task.start()
    def analysis_done(self,result):
        self.analysis.setPlainText(result); self.status.setText("AI analysis complete. Verify every claim against cited evidence.")
    def analysis_failed(self,error):
        self.status.setText("AI analysis unavailable"); QMessageBox.warning(self,"AI analyst",error)
