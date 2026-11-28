"""Social, Telegram and scoped Tor .onion monitoring UI.

Recurring work is local to this desktop installation and runs only while the
application is open. Every monitor is limited to explicit analyst configuration.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from PyQt6.QtCore import QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView,
    QAbstractItemView
)

from .models import Evidence
from .darkweb_monitor import _local_tor_proxy
from .telegram_monitor import normalize_public_channels
from .network import configured_proxy_url


class _ContentWorker(QThread):
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, monitor):
        super().__init__()
        self.monitor = dict(monitor)

    def run(self):
        try:
            from .darkweb_monitor import run_content_monitor
            result = run_content_monitor(self.monitor["kind"], self.monitor["config"])
            self.done.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class ContentMonitoringPanel(QWidget):
    evidence_added = pyqtSignal(str)

    SOURCES = [
        ("Mastodon public account", "mastodon_account"),
        ("Bluesky public search", "bluesky_search"),
        ("Public RSS / Atom feed (including YouTube channel feeds)", "rss_feed"),
        ("Telegram public channels (Bot API)", "telegram_channels"),
        ("Tor v3 .onion public page", "onion_page"),
    ]

    def __init__(self, store, user, parent=None):
        super().__init__(parent)
        self.store = store
        self.user = user
        self.case_id = None
        self.worker = None
        self.active_monitor = None

        root = QVBoxLayout(self)
        title = QLabel("Social media, Telegram & Tor monitoring")
        title.setStyleSheet("font-size:20px;font-weight:800")
        root.addWidget(title)
        intro = QLabel(
            "Monitor public social posts, Telegram channel updates, public RSS/Atom feeds, "
            "and one analyst-specified Tor v3 onion page. No DMs, private groups, login bypass, "
            "link crawling, file downloads or credential-dump collection. Schedules run only "
            "while this desktop app is open."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        form = QHBoxLayout()
        self.source = QComboBox()
        for label, kind in self.SOURCES:
            self.source.addItem(label, kind)
        self.source.currentIndexChanged.connect(self.update_target_hint)
        form.addWidget(self.source, 2)
        self.target = QLineEdit()
        self.target.setPlaceholderText("@account@instance or public profile URL")
        form.addWidget(self.target, 3)
        root.addLayout(form)

        options = QHBoxLayout()
        self.keywords = QLineEdit()
        self.keywords.setPlaceholderText("Optional keywords (comma-separated; any match)")
        options.addWidget(self.keywords, 3)
        self.interval = QComboBox()
        self.interval.addItem("Every 1 hour", 3600)
        self.interval.addItem("Every 6 hours", 21600)
        self.interval.addItem("Every 12 hours", 43200)
        self.interval.addItem("Every 24 hours", 86400)
        self.interval.addItem("Every 7 days", 604800)
        options.addWidget(self.interval, 1)
        self.create_button = QPushButton("Add monitor")
        self.create_button.clicked.connect(self.create_monitor)
        options.addWidget(self.create_button)
        root.addLayout(options)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Source", "Target / query", "Interval", "Next run UTC", "Last result", "Monitor ID"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        root.addWidget(self.table, 1)

        actions = QHBoxLayout()
        self.run_button = QPushButton("Run selected now")
        self.run_button.clicked.connect(self.run_selected)
        actions.addWidget(self.run_button)
        self.remove_button = QPushButton("Remove selected")
        self.remove_button.clicked.connect(self.remove_selected)
        actions.addWidget(self.remove_button)
        actions.addStretch()
        root.addLayout(actions)
        self.status = QLabel("Select a case to configure content monitors.")
        self.status.setWordWrap(True)
        root.addWidget(self.status)

        writable = bool(user and user.get("role") in {"admin", "analyst"})
        self.create_button.setEnabled(writable)
        self.remove_button.setEnabled(writable)
        self.run_button.setEnabled(writable)

        self.timer = QTimer(self)
        self.timer.setInterval(30000)
        self.timer.timeout.connect(self.run_due)
        self.timer.start()
        self.update_target_hint()
        self.refresh()

    def update_target_hint(self):
        kind = self.source.currentData()
        hints = {
            "mastodon_account": "@account@instance or https://instance/@account",
            "bluesky_search": "Public Bluesky search terms",
            "rss_feed": "https://…/feed.xml (RSS/Atom; YouTube channel feed URLs work)",
            "telegram_channels": "@channel_one, @channel_two (public channel usernames)",
            "onion_page": "https://<56-character-v3-address>.onion/path",
        }
        self.target.setPlaceholderText(hints.get(kind, "Public source"))
        self.keywords.setPlaceholderText(
            "Optional terms to match in fetched posts/pages (comma-separated)" if kind != "bluesky_search"
            else "Optional extra terms to match within search results"
        )

    def set_case(self, case_id):
        self.case_id = case_id
        self.refresh()

    def _can_write(self):
        if not self.case_id or not self.user:
            return False
        return self.user.get("role") == "admin" or self.store.user_case_role(self.case_id, self.user) in {"owner", "analyst"}

    def refresh(self):
        rows = self.store.content_monitors(self.case_id) if self.case_id else []
        self.table.setRowCount(len(rows))
        labels = dict((kind, label) for label, kind in self.SOURCES)
        for index, monitor in enumerate(rows):
            config = monitor.get("config", {})
            target = (", ".join(config.get("channels", [])) if monitor["kind"] == "telegram_channels"
                      else config.get("account") or config.get("query") or config.get("feed_url") or config.get("url", ""))
            interval = str(monitor["interval_seconds"] // 3600) + "h"
            if monitor["interval_seconds"] >= 86400:
                interval = str(monitor["interval_seconds"] // 86400) + "d"
            values = [
                labels.get(monitor["kind"], monitor["kind"]),
                target, interval, monitor["next_run_at"],
                monitor.get("last_status", ""), monitor["id"],
            ]
            for column, value in enumerate(values):
                self.table.setItem(index, column, QTableWidgetItem(str(value)))
        if not rows:
            self.status.setText("No social, Telegram or onion monitors are configured for this case.")

    def create_monitor(self):
        if not self._can_write():
            QMessageBox.warning(self, "Case access required", "Select a case where you have analyst or owner permissions.")
            return
        kind = self.source.currentData()
        target = self.target.text().strip()
        if not target:
            QMessageBox.information(self, "Target required", "Enter the public source or search query.")
            return
        keywords = [item.strip() for item in self.keywords.text().split(",") if item.strip()]
        config = {"keywords": keywords}
        try:
            if kind == "mastodon_account":
                config["account"] = target
                if not ("@" in target and ("." in target or "://" in target)):
                    raise ValueError("Use @account@instance or a public Mastodon profile URL.")
            elif kind == "bluesky_search":
                if len(target) < 2 or len(target) > 200:
                    raise ValueError("Bluesky search terms must be 2-200 characters.")
                config["query"] = target
            elif kind == "rss_feed":
                from urllib.parse import urlparse
                parsed = urlparse(target)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
                    raise ValueError("RSS/Atom feeds must be public HTTPS URLs.")
                config["feed_url"] = target
            elif kind == "telegram_channels":
                config["channels"] = normalize_public_channels(target)
                from .providers.ai import get_api_key
                if not get_api_key("telegram_bot_token"):
                    raise ValueError("Save a Telegram Bot API token in AI & network settings first.")
            elif kind == "onion_page":
                from urllib.parse import urlparse
                parsed = urlparse(target)
                if parsed.scheme not in {"https", "http"} or not parsed.hostname or not parsed.hostname.endswith(".onion"):
                    raise ValueError("Enter one exact HTTP(S) v3 .onion page URL.")
                _local_tor_proxy()
                config["url"] = target
            interval = int(self.interval.currentData())
            monitor_id = self.store.create_content_monitor(
                self.case_id, kind, config, interval, self.user["id"]
            )
            self.target.clear()
            self.keywords.clear()
            self.refresh()
            self.status.setText("Monitor " + monitor_id[:8] + " created. Its first check is due now.")
        except Exception as exc:
            QMessageBox.warning(self, "Monitor not created", str(exc))

    def _selected_monitor(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows or not self.case_id:
            return None
        monitor_id = self.table.item(rows[0].row(), 5).text()
        return next((item for item in self.store.content_monitors(self.case_id)
                     if item["id"] == monitor_id), None)

    def run_selected(self):
        monitor = self._selected_monitor()
        if not monitor:
            return
        self._start_monitor(monitor)

    def run_due(self):
        if self.worker and self.worker.isRunning():
            return
        if not self.user or self.user.get("role") not in {"admin", "analyst"}:
            return
        due = self.store.due_content_monitors()
        due = [item for item in due
               if (self.user.get("role") == "admin" or
                   self.store.user_case_role(item["case_id"], self.user) in {"owner", "analyst"})]
        if due:
            self._start_monitor(due[0])

    def _start_monitor(self, monitor):
        if self.worker and self.worker.isRunning():
            return
        if not self.user or self.user.get("role") not in {"admin", "analyst"}:
            QMessageBox.warning(self, "Read-only access", "Only an analyst or administrator can run monitors.")
            return
        role = self.store.user_case_role(monitor["case_id"], self.user)
        if role not in {"owner", "analyst"} and self.user.get("role") != "admin":
            QMessageBox.warning(self, "Access denied", "You do not have write access to this case.")
            return
        self.active_monitor = dict(monitor)
        self.create_button.setEnabled(False)
        self.run_button.setEnabled(False)
        self.status.setText("Checking " + monitor["kind"] + " source…")
        self.worker = _ContentWorker(monitor)
        self.worker.done.connect(self.monitor_complete)
        self.worker.failed.connect(self.monitor_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    def _worker_finished(self):
        self.create_button.setEnabled(self._can_write())
        self.run_button.setEnabled(self._can_write())
        self.refresh()

    def monitor_complete(self, result):
        monitor = self.active_monitor
        if not monitor:
            return
        updated_config = result.get("config", monitor["config"])
        items = result.get("items", [])
        added = 0
        for item in items:
            if not self.store.record_content_monitor_item(monitor["id"], item["item_id"]):
                continue
            content = {
                "text": item.get("text", ""),
                "author": item.get("author", ""),
                "published_at": item.get("published_at", ""),
                "monitor_kind": monitor["kind"],
                "monitor_id": monitor["id"],
                "item_sha256": item.get("sha256", ""),
            }
            evidence = Evidence(
                monitor["case_id"], item.get("source", "Content monitor"),
                item.get("title", "Public content update"), item.get("url", ""),
                json.dumps(content, ensure_ascii=False, indent=2),
                confidence="Low", kind="Public social / channel / onion observation",
            )
            self.store.add_evidence(evidence)
            self.store.append_event(monitor["case_id"], {
                "action": "content_monitor_finding_added", "monitor_id": monitor["id"],
                "evidence_id": evidence.id, "item_id": item["item_id"], "source": item.get("source"),
            })
            added += 1
        next_time = datetime.now(timezone.utc) + timedelta(seconds=int(monitor["interval_seconds"]))
        status = str(result.get("status", "completed")) + "; " + str(added) + " new evidence item(s)"
        self.store.update_content_monitor(monitor["id"], config=updated_config,
                                          next_run_at=next_time.isoformat(), status=status)
        self.status.setText("Monitor complete: " + status)
        if added:
            self.evidence_added.emit(monitor["case_id"])

    def monitor_failed(self, message):
        monitor = self.active_monitor
        if monitor:
            next_time = datetime.now(timezone.utc) + timedelta(seconds=int(monitor["interval_seconds"]))
            self.store.update_content_monitor(monitor["id"], next_run_at=next_time.isoformat(),
                                              status="failed: " + message[:350])
        self.status.setText("Monitor failed: " + message[:350])

    def remove_selected(self):
        monitor = self._selected_monitor()
        if not monitor:
            return
        if self.user.get("role") != "admin" and monitor["created_by"] != self.user["id"]:
            QMessageBox.warning(self, "Permission denied", "Only the schedule creator or administrator can remove it.")
            return
        answer = QMessageBox.question(self, "Remove monitor",
            "Remove this monitor and its local duplicate-tracking data?")
        if answer == QMessageBox.StandardButton.Yes:
            self.store.remove_content_monitor(monitor["id"])
            self.refresh()

    def closeEvent(self, event):
        self.timer.stop()
        super().closeEvent(event)
