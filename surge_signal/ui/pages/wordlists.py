"""Wordlist library, curated catalog and candidate preparation."""

from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...audit.wordlists import CATEGORY_LABELS
from ..widgets import (
    Card,
    Chip,
    InfoBanner,
    KeyValueRow,
    format_bytes,
    format_number,
    make_table,
    open_path,
    set_cell,
    set_chip_cell,
    set_column_widths,
)
from .base import BasePage


class ImportWordlistDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        category: str = "custom",
        suggested_name: str = "",
    ):
        super().__init__(parent)
        self.setWindowTitle("Import wordlist")
        self.setModal(True)
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)
        title = QLabel("Import an approved wordlist")
        title.setProperty("role", "h2")
        layout.addWidget(title)
        note = QLabel(
            "The file is copied into the managed library, hashed and indexed. For "
            "compressed .gz lists, Surge Signal decompresses a managed copy."
        )
        note.setWordWrap(True)
        note.setProperty("role", "small")
        layout.addWidget(note)
        form = QFormLayout()
        form.setSpacing(9)
        self.path = QLineEdit()
        self.path.setPlaceholderText("Select .txt, .lst, .dic, .csv or .gz")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        path_row = QHBoxLayout()
        path_row.addWidget(self.path, 1)
        path_row.addWidget(browse)
        path_holder = QWidget()
        path_holder.setLayout(path_row)
        form.addRow("File", path_holder)
        self.category = QComboBox()
        for key, label in CATEGORY_LABELS.items():
            if key == "prepared":
                continue
            self.category.addItem(label, key)
        index = self.category.findData(category)
        if index >= 0:
            self.category.setCurrentIndex(index)
        self.name = QLineEdit(suggested_name)
        self.name.setPlaceholderText("Optional display name")
        self.description = QTextEdit()
        self.description.setPlaceholderText("Provenance, licence or engagement notes")
        self.description.setFixedHeight(74)
        form.addRow("Category", self.category)
        form.addRow("Name", self.name)
        form.addRow("Description", self.description)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Import")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("variant", "primary")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self._accept)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self,
            "Select wordlist",
            "",
            "Wordlists (*.txt *.lst *.dic *.csv *.gz);;All files (*)",
        )
        if path:
            self.path.setText(path)
            if not self.name.text():
                self.name.setText(Path(path).stem)

    def _accept(self) -> None:
        if not Path(self.path.text().strip()).is_file():
            QMessageBox.warning(self, "Wordlist required", "Select an existing wordlist file.")
            return
        self.accept()

    def values(self) -> tuple[str, str, str, str]:
        return (
            self.path.text().strip(),
            self.category.currentData(),
            self.description.toPlainText().strip(),
            self.name.text().strip(),
        )


class CustomWordlistDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Create custom wordlist")
        self.setModal(True)
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(10)
        title = QLabel("Create a custom contextual list")
        title.setProperty("role", "h2")
        layout.addWidget(title)
        note = QLabel(
            "Use only approved, non-sensitive engagement context. Candidates are "
            "deduplicated exactly and stored as a hashed managed list."
        )
        note.setProperty("role", "small")
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. Lab-SSID-context")
        self.description = QLineEdit()
        self.description.setPlaceholderText("Optional description")
        self.candidates = QTextEdit()
        self.candidates.setPlaceholderText("One candidate per line…")
        self.candidates.setMinimumHeight(190)
        form.addRow("Name", self.name)
        form.addRow("Description", self.description)
        form.addRow("Candidates", self.candidates)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Create list")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("variant", "primary")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self._accept)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        if not self.name.text().strip():
            QMessageBox.warning(self, "Name required", "Give the custom list a name.")
            return
        if not self.candidates.toPlainText().strip():
            QMessageBox.warning(self, "Candidates required", "Add at least one candidate.")
            return
        self.accept()

    def values(self) -> tuple[str, str, list[str]]:
        return (
            self.name.text().strip(),
            self.description.text().strip(),
            self.candidates.toPlainText().splitlines(),
        )


class WordlistsPage(BasePage):
    title = "Wordlist Library"
    subtitle = (
        "Curated collections, provenance and candidate preparation. Lists are "
        "prioritised by category, length-filtered for WPA and deduplicated before use."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._lists: list[dict] = []
        self._catalog: list[dict] = []
        self._build()

    def _build(self) -> None:
        self.scan_button = self.add_action("Scan library", self.scan_library, primary=True)
        self.import_button = self.add_action("Import list", self.import_list)
        self.custom_button = self.add_action("Create custom", self.create_custom)
        self.folder_button = self.add_action("Open folder", self.open_folder)

        summary_card = Card(padding=14, spacing=6)
        summary_row = QHBoxLayout()
        self.summary_label = QLabel("No wordlists registered")
        self.summary_label.setProperty("role", "h2")
        summary_row.addWidget(self.summary_label)
        summary_row.addStretch(1)
        self.prepared_label = QLabel("0 prepared")
        self.prepared_label.setProperty("role", "pill")
        summary_row.addWidget(self.prepared_label)
        summary_card.body.addLayout(summary_row)
        self.summary_detail = QLabel(
            "Import licensed wordlists from the curated catalog or create an "
            "engagement-specific list."
        )
        self.summary_detail.setProperty("role", "small")
        self.summary_detail.setWordWrap(True)
        summary_card.add(self.summary_detail)
        progress_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedHeight(8)
        self.progress_label = QLabel("")
        self.progress_label.setProperty("role", "small")
        progress_row.addWidget(self.progress, 1)
        progress_row.addWidget(self.progress_label)
        summary_card.body.addLayout(progress_row)
        self.content.addWidget(summary_card)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_library_tab(), "Installed lists")
        self.tabs.addTab(self._build_catalog_tab(), "Curated catalog")
        self.content.addWidget(self.tabs, 1)

    def _build_library_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(9)
        toolbar = QHBoxLayout()
        self.library_hint = QLabel(
            "Select one or more lists to use as the source set for an audit."
        )
        self.library_hint.setProperty("role", "small")
        toolbar.addWidget(self.library_hint, 1)
        self.use_button = QPushButton("Use in Password Auditor")
        self.use_button.clicked.connect(self.use_in_auditor)
        toolbar.addWidget(self.use_button)
        self.remove_button = QPushButton("Remove record")
        self.remove_button.setProperty("variant", "danger")
        self.remove_button.clicked.connect(self.remove_selected)
        toolbar.addWidget(self.remove_button)
        layout.addLayout(toolbar)
        self.table = make_table(
            ["Name", "Category", "Lines", "Lengths", "Size", "Priority", "File"],
            stretch_column=0,
        )
        set_column_widths(
            self.table, {1: 150, 2: 82, 3: 82, 4: 85, 5: 75, 6: 85}
        )
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.doubleClicked.connect(lambda _index: self.use_in_auditor())
        layout.addWidget(self.table, 1)
        self.empty = InfoBanner(
            "No lists installed yet. Open the Curated catalog tab, download an "
            "authorised collection from its official source, then use Import list.",
            level="warn",
        )
        layout.addWidget(self.empty)
        return widget

    def _build_catalog_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(9)
        banner = InfoBanner(
            "SURGE Signal does not bundle or silently download third-party password "
            "corpora. Review each licence, download only what the engagement needs, and "
            "keep provenance with the assessment. 'Installed' means a matching managed "
            "file is already indexed.",
        )
        layout.addWidget(banner)
        self.catalog_table = make_table(
            ["Collection", "Category", "Status", "Approx. size", "Licence"], stretch_column=0
        )
        set_column_widths(self.catalog_table, {1: 140, 2: 180, 3: 130})
        self.catalog_table.itemSelectionChanged.connect(self._catalog_selected)
        layout.addWidget(self.catalog_table, 3)
        detail = Card(padding=13, spacing=6)
        self.catalog_title = QLabel("Select a collection")
        self.catalog_title.setProperty("role", "h2")
        detail.add(self.catalog_title)
        self.catalog_description = QLabel(
            "The catalog describes provenance and safe installation guidance."
        )
        self.catalog_description.setProperty("role", "small")
        self.catalog_description.setWordWrap(True)
        detail.add(self.catalog_description)
        self.catalog_guidance = QLabel("")
        self.catalog_guidance.setWordWrap(True)
        self.catalog_guidance.setProperty("role", "muted")
        detail.add(self.catalog_guidance)
        actions = QHBoxLayout()
        self.source_button = QPushButton("Open official source")
        self.source_button.setEnabled(False)
        self.source_button.clicked.connect(self.open_source)
        self.catalog_import_button = QPushButton("Import matching file")
        self.catalog_import_button.setEnabled(False)
        self.catalog_import_button.setProperty("variant", "primary")
        self.catalog_import_button.clicked.connect(self.import_from_catalog)
        actions.addWidget(self.source_button)
        actions.addWidget(self.catalog_import_button)
        actions.addStretch(1)
        detail.body.addLayout(actions)
        layout.addWidget(detail, 2)
        return widget

    def refresh(self) -> None:
        self._lists = self.service.wordlist_records(include_prepared=True)
        self._catalog = self.service.wordlist_catalog()
        total_lines = sum(int(item.get("line_count") or 0) for item in self._lists)
        prepared = sum(1 for item in self._lists if item.get("is_prepared"))
        installed = sum(1 for item in self._lists if not item.get("is_prepared"))
        self.summary_label.setText(f"{installed} managed list(s) · {format_number(total_lines)} candidates")
        self.prepared_label.setText(f"{prepared} prepared")
        categories = {item.get("category") for item in self._lists if not item.get("is_prepared")}
        self.summary_detail.setText(
            f"{len(categories)} categor{'y' if len(categories) == 1 else 'ies'} in use · "
            f"library: {self.service.paths.wordlists}"
        )
        self.table.clearSpans()
        self.table.setRowCount(0)
        for row, record in enumerate(self._lists):
            self.table.insertRow(row)
            name = record["name"]
            if record.get("is_prepared"):
                name = "★ " + name
            set_cell(
                self.table,
                row,
                0,
                name,
                tooltip=record.get("description", ""),
                colour="#f2a36f" if record.get("is_prepared") else None,
            )
            set_chip_cell(
                self.table,
                row,
                1,
                record.get("category_label", record.get("category", "")).upper(),
                "#f26a21" if record.get("is_prepared") else "#6cb6ff",
            )
            set_cell(self.table, row, 2, format_number(record.get("line_count")))
            length = (
                f"{record.get('min_length') or '?'}–{record.get('max_length') or '?'}"
            )
            set_cell(self.table, row, 3, length)
            set_cell(self.table, row, 4, format_bytes(record.get("size_bytes")))
            set_cell(self.table, row, 5, str(record.get("priority", "—")))
            exists = record.get("exists", True)
            set_cell(
                self.table,
                row,
                6,
                "present" if exists else "missing",
                colour="#4ade80" if exists else "#ff6b7a",
            )
        if not self._lists:
            self.table.setRowCount(1)
            set_cell(self.table, 0, 0, "No wordlists installed.", colour="#a8a8a8")
            self.table.setSpan(0, 0, 1, 7)
        self.empty.setVisible(not self._lists)
        self.remove_button.setEnabled(bool(self.table.selectionModel().selectedRows()))
        self.use_button.setEnabled(bool(self.table.selectionModel().selectedRows()))
        self._fill_catalog()

    def _fill_catalog(self) -> None:
        self.catalog_table.setRowCount(0)
        for row, entry in enumerate(self._catalog):
            self.catalog_table.insertRow(row)
            set_cell(self.catalog_table, row, 0, entry["name"], tooltip=entry["description"])
            set_cell(self.catalog_table, row, 1, entry["category_label"])
            status = (
                f"Installed ({entry['installed_count']} file(s))"
                if entry["installed"]
                else "Not installed"
            )
            set_cell(
                self.catalog_table,
                row,
                2,
                status,
                colour="#4ade80" if entry["installed"] else "#a8a8a8",
            )
            set_cell(self.catalog_table, row, 3, entry["approximate_size"])
            set_cell(
                self.catalog_table,
                row,
                4,
                "Essential" if entry["essential"] else "Optional",
                colour="#f26a21" if entry["essential"] else "#a8a8a8",
            )
        self._catalog_selected()

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        enabled = bool(rows)
        self.remove_button.setEnabled(enabled)
        self.use_button.setEnabled(enabled)

    def selected_ids(self) -> list[int]:
        ids: list[int] = []
        for index in self.table.selectionModel().selectedRows():
            row = index.row()
            if row < len(self._lists):
                ids.append(int(self._lists[row]["id"]))
        return ids

    def select_wordlist(self, wordlist_id: int) -> None:
        for row, record in enumerate(self._lists):
            if int(record["id"]) == wordlist_id:
                self.table.selectRow(row)
                self.table.scrollToItem(self.table.item(row, 0))
                break

    def use_in_auditor(self) -> None:
        ids = self.selected_ids()
        if not ids:
            return
        self.window.navigate("auditor")
        self.window.pages["auditor"].select_wordlists(ids)
        self.notify(
            f"{len(ids)} wordlist(s) selected. Prepare and run the audit from the "
            "Password Auditor.",
            "info",
        )

    def scan_library(self) -> None:
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning…")
        self.progress.setVisible(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress_label.setText("Scanning library…")

        def progress(value) -> None:
            done, total, name = value
            self.progress.setRange(0, max(1, total))
            self.progress.setValue(done)
            self.progress_label.setText(f"{done}/{total} · {name}")

        def done(result) -> None:
            self.scan_button.setEnabled(True)
            self.scan_button.setText("Scan library")
            self.progress.setVisible(False)
            self.progress_label.setText("")
            self.refresh()
            message = f"Library scan complete: {result.registered} list(s) registered, {result.skipped} skipped."
            self.notify(message, "success" if not result.errors else "warn")
            if result.errors:
                QMessageBox.information(
                    self,
                    "Library scan notes",
                    message + "\n\n" + "\n".join(result.errors[:10]),
                )

        def failed(message: str) -> None:
            self.scan_button.setEnabled(True)
            self.scan_button.setText("Scan library")
            self.progress.setVisible(False)
            self.progress_label.setText("")
            self.notify(f"Library scan failed: {message}", "error")

        self.tasks.start(
            lambda progress_cb: self.service.scan_wordlists(progress=lambda a, b, c: progress_cb((a, b, c))),
            on_done=done,
            on_error=failed,
            on_progress=progress,
            with_progress=True,
        )

    def import_list(self) -> None:
        dialog = ImportWordlistDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        path, category, description, name = dialog.values()
        self._run_import(path, category, description, name)

    def import_from_catalog(self) -> None:
        rows = self.catalog_table.selectionModel().selectedRows()
        if not rows:
            return
        entry = self._catalog[rows[0].row()]
        dialog = ImportWordlistDialog(
            self, category=entry["category"], suggested_name=entry["name"]
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        path, category, description, name = dialog.values()
        self._run_import(
            path,
            category,
            description or f"{entry['name']}: {entry['license_note']}",
            name,
        )

    def _run_import(self, path: str, category: str, description: str, name: str) -> None:
        self.import_button.setEnabled(False)
        self.import_button.setText("Importing…")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.progress_label.setText("Copying and hashing list…")
        self.notify("Importing wordlist into the managed library…")

        def done(record) -> None:
            self.import_button.setEnabled(True)
            self.import_button.setText("Import list")
            self.progress.setVisible(False)
            self.progress.setRange(0, 1)
            self.progress_label.setText("")
            self.refresh()
            self.select_wordlist(int(record["id"]))
            self.notify(
                f"Imported {record['name']} ({format_number(record['line_count'])} lines).",
                "success",
            )

        def failed(message: str) -> None:
            self.import_button.setEnabled(True)
            self.import_button.setText("Import list")
            self.progress.setVisible(False)
            self.progress_label.setText("")
            self.notify(f"Import failed: {message}", "error")
            QMessageBox.warning(self, "Wordlist import failed", message)

        self.tasks.start(
            lambda: self.service.import_wordlist(path, category, description, name or None),
            on_done=done,
            on_error=failed,
        )

    def create_custom(self) -> None:
        dialog = CustomWordlistDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, description, candidates = dialog.values()
        self.custom_button.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.notify("Creating custom wordlist…")

        def done(record) -> None:
            self.custom_button.setEnabled(True)
            self.progress.setVisible(False)
            self.refresh()
            self.select_wordlist(int(record["id"]))
            self.notify(f"Custom list '{record['name']}' created.", "success")

        def failed(message: str) -> None:
            self.custom_button.setEnabled(True)
            self.progress.setVisible(False)
            self.notify(f"Custom list failed: {message}", "error")

        self.tasks.start(
            lambda: self.service.wordlists.create_custom_list(name, candidates, description),
            on_done=done,
            on_error=failed,
        )

    def remove_selected(self) -> None:
        ids = self.selected_ids()
        if not ids:
            return
        record = next(item for item in self._lists if int(item["id"]) == ids[0])
        answer = QMessageBox.question(
            self,
            "Remove wordlist record",
            f"Remove '{record['name']}' from the Surge Signal library index?\n\n"
            "The file will remain on disk. Prepared candidate files can be regenerated.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            for wordlist_id in ids:
                self.service.remove_wordlist(wordlist_id, delete_file=False)
            self.refresh()
            self.notify("Wordlist record(s) removed. Files remain on disk.", "success")
        except Exception as exc:                
            QMessageBox.warning(self, "Remove failed", str(exc))

    def _catalog_selected(self) -> None:
        rows = self.catalog_table.selectionModel().selectedRows()
        if not rows:
            self.catalog_title.setText("Select a collection")
            self.catalog_description.setText(
                "The catalog describes provenance and safe installation guidance."
            )
            self.catalog_guidance.setText("")
            self.source_button.setEnabled(False)
            self.catalog_import_button.setEnabled(False)
            return
        entry = self._catalog[rows[0].row()]
        self.catalog_title.setText(entry["name"])
        self.catalog_description.setText(
            f"{entry['description']}\n\nLicence: {entry['license_note']}"
        )
        self.catalog_guidance.setText(
            f"Approximate size: {entry['approximate_size']}. {entry['guidance']}"
        )
        self.source_button.setEnabled(bool(entry["source_url"]))
        self.source_button.setProperty("url", entry["source_url"])
        self.catalog_import_button.setEnabled(True)

    def open_source(self) -> None:
        url = self.source_button.property("url")
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def open_folder(self) -> None:
        open_path(self.service.paths.wordlists)

