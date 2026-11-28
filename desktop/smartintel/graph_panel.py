"""Interactive evidence graph with filtering, connected-component clusters and force layout."""
from __future__ import annotations
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QPen, QColor, QFont
from PyQt6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QComboBox,
    QLineEdit,QGraphicsView,QGraphicsScene,QGraphicsEllipseItem,QGraphicsSimpleTextItem,
    QGraphicsLineItem,QTextBrowser,QSplitter,QMessageBox)
from .identity_graph import build_identity_graph, validate_graph
from .graph_algorithms import connected_components, filter_graph, force_layout
from .match_scoring import assess_evidence_risk
from .ai_analysis import analyze_evidence

class _GraphView(QGraphicsView):
    """Mouse-wheel zoom and hand-drag navigation."""
    def __init__(self,scene,parent=None):
        super().__init__(scene,parent)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
    def wheelEvent(self,event):
        self.scale(1.18 if event.angleDelta().y()>0 else 1/1.18,1.18 if event.angleDelta().y()>0 else 1/1.18)

class _AnalystTask(QThread):
    done=pyqtSignal(str); failed=pyqtSignal(str)
    def __init__(self,question,graph,risk,provider,evidence):
        super().__init__(); self.args=(question,graph,risk,provider,evidence)
    def run(self):
        try:self.done.emit(analyze_evidence(*self.args))
        except Exception as exc:self.failed.emit(str(exc))

class _NodeItem(QGraphicsEllipseItem):
    def __init__(self,node,x,y,cluster,callback):
        super().__init__(-48,-25,96,50); self.node=node; self.callback=callback
        palette=["#286b66","#75532c","#51458a","#315b83","#75506f","#45623e","#79504a"]
        self.setBrush(QBrush(QColor(palette[cluster%len(palette)])))
        self.setPen(QPen(QColor("#d4def0"),1.5)); self.setPos(x,y); self.setZValue(2)
        self.setToolTip(f"Cluster {cluster+1} · {node.kind} · {node.label}")
        label=QGraphicsSimpleTextItem(node.label[:20],self); label.setBrush(QBrush(QColor("#ffffff")))
        label.setFont(QFont("Segoe UI",8)); rect=label.boundingRect(); label.setPos(-rect.width()/2,-rect.height()/2)
    def mousePressEvent(self,event):
        self.callback(self.node); super().mousePressEvent(event)

class IdentityGraphPanel(QWidget):
    def __init__(self,store,parent=None):
        super().__init__(parent); self.store=store; self.case_id=None; self.graph=None
        self.evidence=[]; self.task=None; self.selected=None
        root=QVBoxLayout(self); root.setContentsMargins(8,8,8,8)
        header=QHBoxLayout(); title=QLabel("Evidence relationship graph")
        title.setStyleSheet("font-size:19px;font-weight:800"); header.addWidget(title); header.addStretch()
        self.refresh_btn=QPushButton("Refresh graph"); self.refresh_btn.clicked.connect(self.refresh); header.addWidget(self.refresh_btn)
        root.addLayout(header)
        note=QLabel("Force-directed layout · connected-component clusters · filter by identifier and relationship. Lines show co-observation, not proof of identity.")
        note.setWordWrap(True); note.setStyleSheet("color:#91a2bd"); root.addWidget(note)
        filters=QHBoxLayout()
        self.kind_filter=QComboBox(); self.kind_filter.addItems(["All types","source","email","phone","username","profile_or_url"])
        self.edge_filter=QComboBox(); self.edge_filter.addItems(["All relationships","observed_in","co_observed"])
        self.search_filter=QLineEdit(); self.search_filter.setPlaceholderText("Filter labels…")
        for control in (self.kind_filter,self.edge_filter,self.search_filter): filters.addWidget(control)
        self.kind_filter.currentTextChanged.connect(self.render_graph)
        self.edge_filter.currentTextChanged.connect(self.render_graph)
        self.search_filter.textChanged.connect(self.render_graph)
        root.addLayout(filters)
        split=QSplitter(Qt.Orientation.Horizontal); self.scene=QGraphicsScene(self); self.view=_GraphView(self.scene)
        self.view.setMinimumHeight(360); self.view.setStyleSheet("background:#091323;border:1px solid #263650;border-radius:8px")
        split.addWidget(self.view)
        side=QWidget(); sv=QVBoxLayout(side); self.detail=QTextBrowser(); self.detail.setMinimumWidth(270); sv.addWidget(self.detail,1)
        self.risk=QLabel("False-positive risk index: —"); self.risk.setWordWrap(True)
        self.risk.setStyleSheet("font-weight:800;padding:8px;background:#17243a;border-radius:7px"); sv.addWidget(self.risk)
        row=QHBoxLayout(); self.provider=QComboBox(); self.provider.addItems(["Ollama","OpenAI","Gemini","Claude"]); row.addWidget(self.provider)
        self.analyze_btn=QPushButton("Analyze graph with AI"); self.analyze_btn.clicked.connect(self.run_analysis); row.addWidget(self.analyze_btn); sv.addLayout(row)
        self.analysis=QTextBrowser(); self.analysis.setPlaceholderText("AI analysis will appear here."); sv.addWidget(self.analysis,2)
        split.addWidget(side); split.setSizes([700,360]); root.addWidget(split,1)
        self.status=QLabel("Select a case and refresh to build its graph."); self.status.setStyleSheet("color:#91a2bd"); root.addWidget(self.status)
    def set_case(self,case_id):
        self.case_id=case_id; self.selected=None; self.refresh()
    def refresh(self):
        if not self.case_id:return
        self.evidence=self.store.evidence(self.case_id)
        self.graph=build_identity_graph(self.evidence); validate_graph(self.graph)
        self.render_graph()
    def render_graph(self,*_):
        self.scene.clear(); self.selected=None
        if not self.graph:return
        nodes,edges=filter_graph(self.graph,self.kind_filter.currentText(),self.edge_filter.currentText(),self.search_filter.text())
        if not nodes:
            self.detail.setPlainText("No graph nodes match the current filters.")
            self.risk.setText("False-positive risk index: —"); self.status.setText("No matching nodes."); return
        clusters=connected_components(nodes,edges); positions=force_layout(nodes,edges)
        for edge in edges:
            x1,y1=positions[edge.source]; x2,y2=positions[edge.target]
            line=QGraphicsLineItem(x1,y1,x2,y2)
            color="#7085a8" if edge.relation=="observed_in" else "#9b82c7"
            line.setPen(QPen(QColor(color),1.5 if edge.relation=="observed_in" else 2.0))
            line.setZValue(0); self.scene.addItem(line)
        for node in nodes:
            x,y=positions[node.id]; self.scene.addItem(_NodeItem(node,x,y,clusters[node.id],self.select_node))
        rect=self.scene.itemsBoundingRect().adjusted(-90,-90,90,90); self.scene.setSceneRect(rect)
        self.view.fitInView(rect,Qt.AspectRatioMode.KeepAspectRatio)
        cluster_count=len(set(clusters.values()))
        self.status.setText(f"{len(nodes)} visible nodes · {len(edges)} visible links · {cluster_count} clusters · {len(self.evidence)} evidence records")
        self.detail.setPlainText("Click a node to inspect its supporting evidence. Cluster colours represent graph connectivity only.")
    def select_node(self,node):
        self.selected=node; related=[e for e in self.evidence if e.id in node.evidence_ids]
        risk=assess_evidence_risk(related)
        self.risk.setText(f"Selected-node evidence risk: {risk.score}/100 ({risk.risk_band.upper()})\nUncalibrated heuristic — not a probability or identity confidence.")
        sources={e.source for e in related}
        lines=[f"{node.kind.upper()}: {node.label}",f"Supporting evidence records: {len(related)}",
               f"Distinct source labels: {len(sources)} (independence not assumed)",""]
        for item in related:
            lines.extend([f"• {item.title}",f"  Source: {item.source}",f"  Evidence ID: {item.id}",
                          f"  URL: {item.url or 'Not supplied'}",""])
        self.detail.setPlainText("\n".join(lines))
    def run_analysis(self):
        if not self.graph or not self.evidence:
            QMessageBox.information(self,"No graph","Collect or add evidence to this case first."); return
        risk=assess_evidence_risk(self.evidence).to_dict()
        question="Analyze this case graph. Identify supported connections, weak leads, contradictions and safe next steps."
        self.analyze_btn.setEnabled(False); self.status.setText("AI analysis running…")
        self.task=_AnalystTask(question,self.graph.to_dict(),risk,self.provider.currentText(),self.evidence)
        self.task.done.connect(self.analysis_done); self.task.failed.connect(self.analysis_failed)
        self.task.finished.connect(lambda:self.analyze_btn.setEnabled(True)); self.task.start()
    def analysis_done(self,result):
        self.analysis.setPlainText(result); self.status.setText("AI analysis complete. Verify every claim against cited evidence.")
    def analysis_failed(self,error):
        self.status.setText("AI analysis unavailable"); QMessageBox.warning(self,"AI analyst",error)
