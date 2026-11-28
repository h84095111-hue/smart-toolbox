"""Recurring passive public-source case monitoring.

Schedules are local to this desktop installation. They run through the same
passive workflow/adapters as interactive scans and never trigger active checks.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from PyQt6.QtCore import QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox
)

from .collectors.all_in_one import run_all, _target_kind
from .models import Evidence


class _MonitorWorker(QThread):
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, schedule):
        super().__init__()
        self.schedule = dict(schedule)

    def run(self):
        try:
            self.done.emit(run_all(self.schedule["target"]))
        except Exception as exc:
            self.failed.emit(str(exc))


class MonitoringPanel(QWidget):
    evidence_added = pyqtSignal(str)
    def __init__(self, store, user, parent=None):
        super().__init__(parent)
        self.store = store
        self.user = user
        self.case_id = None
        self.worker = None
        self.active_schedule = None
        root = QVBoxLayout(self)
        title = QLabel("Scheduled passive monitoring")
        title.setStyleSheet("font-size:19px;font-weight:800")
        root.addWidget(title)
        note = QLabel("Local recurring checks for public domains and globally routable IPs. Uses passive connectors only; each run is recorded as case evidence.")
        note.setWordWrap(True)
        root.addWidget(note)
        row = QHBoxLayout()
        self.target = QLineEdit()
        self.target.setPlaceholderText("Domain, public IP or public website URL")
        self.interval = QComboBox()
        self.interval.addItem("Every 1 hour", 3600)
        self.interval.addItem("Every 6 hours", 21600)
        self.interval.addItem("Every 12 hours", 43200)
        self.interval.addItem("Every 24 hours", 86400)
        self.interval.addItem("Every 7 days", 604800)
        self.add_button = QPushButton("Schedule passive checks")
        self.add_button.clicked.connect(self.add_schedule)
        row.addWidget(self.target, 3)
        row.addWidget(self.interval, 1)
        row.addWidget(self.add_button, 2)
        root.addLayout(row)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Target", "Interval", "Next run UTC", "Last result", "Schedule ID"])
        self.table.horizontalHeader().setSectionResizeMode(0, self.table.horizontalHeader().ResizeMode.Stretch)
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        root.addWidget(self.table, 1)
        actions = QHBoxLayout()
        self.remove_button = QPushButton("Remove selected schedule")
        self.remove_button.clicked.connect(self.remove_selected)
        actions.addWidget(self.remove_button)
        self.run_button = QPushButton("Run due checks now")
        self.run_button.clicked.connect(self.run_due)
        actions.addWidget(self.run_button)
        actions.addStretch()
        root.addLayout(actions)
        self.status = QLabel("No active case selected.")
        root.addWidget(self.status)
        writable = user and user.get("role") in {"admin", "analyst"}
        self.add_button.setEnabled(bool(writable))
        self.remove_button.setEnabled(bool(writable))
        self.timer = QTimer(self)
        self.timer.setInterval(30000)
        self.timer.timeout.connect(self.run_due)
        self.timer.start()
        self.refresh()

    def set_case(self, case_id):
        self.case_id = case_id
        self.refresh()

    def refresh(self):
        rows = self.store.monitor_schedules(self.case_id) if self.case_id else []
        self.table.setRowCount(len(rows))
        for i, item in enumerate(rows):
            interval = str(item["interval_seconds"] // 3600) + "h"
            if item["interval_seconds"] >= 86400:
                interval = str(item["interval_seconds"] // 86400) + "d"
            values = [item["target"], interval, item["next_run_at"], item.get("last_status", ""), item["id"]]
            for j, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if j == 4:
                    cell.setData(32, item["id"])
                self.table.setItem(i, j, cell)
        if not rows:
            self.status.setText("No schedules for the selected case.")

    def add_schedule(self):
        if not self.case_id:
            QMessageBox.information(self, "Select a case", "Create or select a case first.")
            return
        if not self.user or self.user.get("role") not in {"admin", "analyst"}:
            QMessageBox.warning(self, "Read-only access", "Only an analyst or administrator can create schedules.")
            return
        raw = self.target.text().strip()
        try:
            kind, normalized, _ = _target_kind(raw)
            if kind not in {"domain", "url", "ip"}:
                raise ValueError("Monitoring supports only public domain, public URL and public IP targets.")
            if kind == "ip":
                import ipaddress
                if not ipaddress.ip_address(normalized).is_global:
                    raise ValueError("Only globally routable IP addresses can be monitored.")
            interval = int(self.interval.currentData())
            self.store.add_monitor_schedule(self.case_id, raw, interval, self.user["id"])
            self.target.clear()
            self.refresh()
            self.status.setText("Passive monitoring schedule saved locally.")
        except Exception as exc:
            QMessageBox.warning(self, "Schedule not created", str(exc))

    def remove_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        schedule_id = self.table.item(rows[0].row(), 4).text()
        schedules = self.store.monitor_schedules(self.case_id)
        item = next((row for row in schedules if row["id"] == schedule_id), None)
        if not item:
            return
        if self.user.get("role") != "admin" and item["created_by"] != self.user["id"]:
            QMessageBox.warning(self, "Permission denied", "Only the schedule creator or an administrator can remove it.")
            return
        answer = QMessageBox.question(self, "Remove schedule", "Remove this recurring passive monitor?")
        if answer == QMessageBox.StandardButton.Yes:
            self.store.remove_monitor_schedule(schedule_id)
            self.refresh()

    def run_due(self):
        if self.worker and self.worker.isRunning():
            return
        now = datetime.now(timezone.utc)
        due = self.store.due_monitor_schedules(now)
        if self.user and self.user.get("role") != "admin":
            due = [row for row in due if row["created_by"] == self.user["id"]]
        if not due:
            self.refresh()
            return
        schedule = due[0]
        role = self.store.user_case_role(schedule["case_id"], self.user)
        if role not in {"owner", "analyst"} and self.user.get("role") != "admin":
            self.store.update_monitor_schedule(schedule["id"], enabled=False, status="paused: account has read-only or no case access")
            self.refresh()
            return
        self.active_schedule = schedule
        self.run_button.setEnabled(False)
        self.status.setText("Running passive monitor for " + schedule["target"])
        self.worker = _MonitorWorker(schedule)
        self.worker.done.connect(self.complete_run)
        self.worker.failed.connect(self.failed_run)
        self.worker.finished.connect(lambda: self.run_button.setEnabled(True))
        self.worker.start()

    def _advance(self, schedule, status):
        next_time = datetime.now(timezone.utc) + timedelta(seconds=int(schedule["interval_seconds"]))
        self.store.update_monitor_schedule(schedule["id"], next_run_at=next_time.isoformat(), status=status)

    def complete_run(self, result):
        schedule = self.active_schedule
        added = 0
        for item in result.get("findings", []):
            evidence = Evidence(schedule["case_id"], item.get("source", "Passive monitor"),
                item.get("title", "Scheduled public-source result"), item.get("url", ""),
                item.get("content", ""), confidence=item.get("confidence", "Low"),
                kind="Scheduled passive monitoring")
            self.store.add_evidence(evidence)
            added += 1
        status = result.get("status", "completed") + "; " + str(added) + " findings"
        if result.get("failures"):
            status += "; " + str(len(result["failures"])) + " source failures"
        self._advance(schedule, status)
        self.status.setText("Monitor complete: " + status)
        self.evidence_added.emit(schedule["case_id"])
        self.refresh()

    def failed_run(self, message):
        schedule = self.active_schedule
        self._advance(schedule, "failed: " + message[:350])
        self.status.setText("Monitor failed: " + message[:350])
        self.refresh()

    def closeEvent(self, event):
        self.timer.stop()
        super().closeEvent(event)
