from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QMessageBox,
    QFileDialog, 
    QInputDialog,
    QLineEdit
)

import rsa_keyring.keyring_services as keyring_services
from gui.generate_key_dialog import GenerateKeyDialog


METADATA_BEGIN = "# PGP-APP-METADATA-BEGIN"
METADATA_END = "# PGP-APP-METADATA-END"

class KeyCard(QFrame):
    def __init__(self, entry: dict, key_type: str, on_click):
        super().__init__()

        self.entry = entry
        self.key_type = key_type
        self.on_click = on_click

        self.setObjectName("KeyCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        key_id_label = QLabel(entry.get("key_id", ""))
        key_id_label.setObjectName("KeyCardId")

        email = entry.get("email", "")
        email_label = QLabel(email if email else "No email")
        email_label.setObjectName("KeyCardEmail")

        name = entry.get("user_name", "")
        name_label = QLabel(name if name else "No name")
        name_label.setObjectName("KeyCardName")

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(5)
        layout.addWidget(key_id_label)
        layout.addWidget(email_label)
        layout.addWidget(name_label)

        self.setLayout(layout)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.on_click(self.entry, self.key_type)

        super().mousePressEvent(event)


class KeyManagementPage(QWidget):
    def __init__(self):
        super().__init__()

        keyring_services.initialize_keyrings()

        self.selected_entry = None
        self.selected_key_type = None

        title = QLabel("Key Management")
        title.setObjectName("PageTitle")

        self.private_cards_layout = QVBoxLayout()
        self.private_cards_layout.setContentsMargins(8, 8, 8, 8)
        self.private_cards_layout.setSpacing(8)
        self.private_cards_layout.addStretch()

        self.public_cards_layout = QVBoxLayout()
        self.public_cards_layout.setContentsMargins(8, 8, 8, 8)
        self.public_cards_layout.setSpacing(8)
        self.public_cards_layout.addStretch()

        private_scroll = self.create_scroll_area(self.private_cards_layout)
        public_scroll = self.create_scroll_area(self.public_cards_layout)

        private_group = QGroupBox("Private Key Ring")
        private_group_layout = QVBoxLayout()
        private_group_layout.addWidget(private_scroll)
        private_group.setLayout(private_group_layout)

        public_group = QGroupBox("Public Key Ring")
        public_group_layout = QVBoxLayout()
        public_group_layout.addWidget(public_scroll)
        public_group.setLayout(public_group_layout)

        cards_widget = QWidget()
        cards_layout = QHBoxLayout()
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(8)
        cards_layout.addWidget(private_group)
        cards_layout.addWidget(public_group)
        cards_widget.setLayout(cards_layout)

        self.details_content = QWidget()
        self.details_layout = QVBoxLayout()
        self.details_layout.setContentsMargins(8, 8, 8, 8)
        self.details_layout.setSpacing(6)

        self.details_placeholder = QLabel("Select a key card to view details.")
        self.details_placeholder.setObjectName("DetailsPlaceholder")
        self.details_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.details_layout.addWidget(self.details_placeholder)
        self.details_layout.addStretch()
        self.details_content.setLayout(self.details_layout)

        details_scroll = QScrollArea()
        details_scroll.setObjectName("DetailsScroll")
        details_scroll.setWidgetResizable(True)
        details_scroll.setWidget(self.details_content)

        self.details_group = QGroupBox("Key Details")
        details_group_layout = QVBoxLayout()
        details_group_layout.addWidget(details_scroll)
        self.details_group.setLayout(details_group_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(cards_widget)
        splitter.addWidget(self.details_group)
        splitter.setSizes([260, 360])
        splitter.setChildrenCollapsible(False)

        self.generate_button = QPushButton("Generate New Key Pair")
        self.import_button = QPushButton("Import Key(s)")
        self.export_button = QPushButton("Export Key(s)")
        self.delete_button = QPushButton("Delete Key")

        self.export_button.setEnabled(False)
        self.delete_button.setEnabled(False)

        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(0, 0, 0, 0)
        buttons_layout.setSpacing(8)
        buttons_layout.addWidget(self.generate_button)
        buttons_layout.addWidget(self.import_button)
        buttons_layout.addWidget(self.export_button)
        buttons_layout.addWidget(self.delete_button)

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(8)
        root_layout.addWidget(title)
        root_layout.addWidget(splitter, stretch=1)
        root_layout.addLayout(buttons_layout)

        self.setLayout(root_layout)


        self.apply_local_styles()
        self.refresh_cards()
        self.generate_button.clicked.connect(self.on_generate_clicked)
        self.export_button.clicked.connect(self.on_export_clicked)
        self.import_button.clicked.connect(self.on_import_clicked)
        self.delete_button.clicked.connect(self.on_delete_clicked)

    def create_scroll_area(self, content_layout):
        content = QWidget()
        content.setLayout(content_layout)

        scroll = QScrollArea()
        scroll.setObjectName("CardsScroll")
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)

        return scroll

    def refresh_cards(self):
        self.clear_cards(self.private_cards_layout)
        self.clear_cards(self.public_cards_layout)

        private_keys = keyring_services.get_private_keys()
        public_keys = keyring_services.get_public_keys()

        if private_keys:
            for entry in private_keys:
                self.private_cards_layout.insertWidget(
                    self.private_cards_layout.count() - 1,
                    KeyCard(entry, "private", self.show_entry_details),
                )
        else:
            self.private_cards_layout.insertWidget(
                self.private_cards_layout.count() - 1,
                self.empty_label("No private keys."),
            )

        if public_keys:
            for entry in public_keys:
                self.public_cards_layout.insertWidget(
                    self.public_cards_layout.count() - 1,
                    KeyCard(entry, "public", self.show_entry_details),
                )
        else:
            self.public_cards_layout.insertWidget(
                self.public_cards_layout.count() - 1,
                self.empty_label("No public keys."),
            )

    def clear_cards(self, layout):
        while layout.count() > 1:
            item = layout.takeAt(0)
            widget = item.widget()

            if widget is not None:
                widget.deleteLater()

    def empty_label(self, text):
        label = QLabel(text)
        label.setObjectName("EmptyLabel")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return label

    def show_entry_details(self, entry: dict, key_type: str):
        self.selected_entry = entry
        self.selected_key_type = key_type

        self.export_button.setEnabled(True)
        self.delete_button.setEnabled(True)

        self.clear_details()

        title = QLabel(f"{key_type.capitalize()} Key")
        title.setObjectName("DetailsTitle")
        self.details_layout.addWidget(title)

        ordered_keys = [
            "key_id",
            "user_name",
            "email",
            "timestamp",
            "key_size",
            "source",
            "is_active",
            "public_key_pem",
            "encrypted_private_key_pem",
        ]

        shown = set()

        for key in ordered_keys:
            if key in entry:
                self.details_layout.addWidget(self.detail_row(key, entry[key]))
                shown.add(key)

        for key, value in entry.items():
            if key not in shown:
                self.details_layout.addWidget(self.detail_row(key, value))

        self.details_layout.addStretch()

    def clear_details(self):
        while self.details_layout.count():
            item = self.details_layout.takeAt(0)
            widget = item.widget()

            if widget is not None:
                widget.deleteLater()

    def detail_row(self, key, value):
        row = QFrame()
        row.setObjectName("DetailRow")

        key_label = QLabel(str(key))
        key_label.setObjectName("DetailKey")
        key_label.setFixedWidth(190)
        key_label.setAlignment(Qt.AlignmentFlag.AlignTop)

        value_label = QLabel(self.format_detail_value(key, value))
        value_label.setObjectName("DetailValue")
        value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        value_label.setWordWrap(True)

        layout = QHBoxLayout()
        layout.setContentsMargins(8, 5, 8, 5)
        layout.setSpacing(12)
        layout.addWidget(key_label)
        layout.addWidget(value_label, stretch=1)

        row.setLayout(layout)

        return row

    def format_detail_value(self, key, value):
        if key == "timestamp":
            return self.format_timestamp(value)

        if isinstance(value, bool):
            return "Yes" if value else "No"

        return str(value)

    def format_timestamp(self, timestamp):
        if timestamp is None:
            return ""

        try:
            return datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(timestamp)

    def apply_local_styles(self):
        self.setStyleSheet("""
        #CardsScroll,
        #DetailsScroll {
            background-color: #151b20;
            border: none;
        }

        #CardsScroll > QWidget,
        #DetailsScroll > QWidget {
            background-color: #151b20;
        }

        #KeyCard {
            background-color: #202830;
            border: 1px solid #4d5962;
            border-radius: 7px;
        }

        #KeyCard:hover {
            background-color: #2b3540;
            border: 1px solid #b8b08a;
        }

        #KeyCard QLabel {
            background-color: transparent;
            border: none;
        }

        #KeyCardId {
            color: #ffffff;
            font-weight: bold;
            font-size: 13px;
        }

        #KeyCardEmail {
            color: #e6e6e6;
            font-size: 13px;
        }

        #KeyCardName {
            color: #aeb7bf;
            font-size: 12px;
        }

        #EmptyLabel {
            background-color: transparent;
            color: #7f8a92;
            padding: 20px;
        }

        #DetailsPlaceholder {
            background-color: transparent;
            color: #7f8a92;
            font-size: 14px;
        }

        #DetailsTitle {
            background-color: transparent;
            color: #ffffff;
            font-size: 16px;
            font-weight: bold;
            padding-bottom: 6px;
        }

        #DetailRow {
            background-color: #1b2228;
            border: 1px solid #26313a;
            border-radius: 4px;
        }

        #DetailKey {
            background-color: transparent;
            color: #b8b08a;
            font-weight: bold;
        }

        #DetailValue {
            background-color: transparent;
            color: #e6e6e6;
        }
        """)
    
    def reset_details_panel(self):
        self.selected_entry = None
        self.selected_key_type = None

        self.export_button.setEnabled(False)
        self.delete_button.setEnabled(False)

        self.clear_details()

        self.details_placeholder = QLabel("Select a key card to view details.")
        self.details_placeholder.setObjectName("DetailsPlaceholder")
        self.details_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.details_layout.addWidget(self.details_placeholder)
        self.details_layout.addStretch()

    def on_generate_clicked(self):
        dialog = GenerateKeyDialog(self)

        if dialog.exec() != GenerateKeyDialog.DialogCode.Accepted:
            return

        data = dialog.get_data()

        try:
            public_entry, private_entry = keyring_services.generate_key_pair(
                user_name=data["user_name"],
                email=data["email"],
                key_size=data["key_size"],
                password=data["password"],
            )

            self.refresh_cards()
            self.show_entry_details(private_entry, "private")

            QMessageBox.information(
                self,
                "Key Pair Generated",
                "New RSA key pair has been generated successfully.",
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Key Generation Failed",
                str(e),
            )

    def on_import_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Key",
            "",
            "PEM Files (*.pem);;All Files (*)",
        )

        if not file_path:
            return

        metadata = self.extract_key_file_metadata(file_path)
        has_owner_metadata = bool(metadata.get("user_name") and metadata.get("email"))
        timestamp = self.metadata_timestamp(metadata)

        if has_owner_metadata:
            user_name = metadata.get("user_name", "")
            email = metadata.get("email", "")
        else:
            user_name, ok = QInputDialog.getText(
                self,
                "Key Owner",
                "Name:",
                text=metadata.get("user_name", ""),
            )

            if not ok:
                return

            email, ok = QInputDialog.getText(
                self,
                "Key Owner",
                "Email:",
                text=metadata.get("email", ""),
            )

            if not ok:
                return

        try:
            result = keyring_services.import_key(
                file_path=file_path,
                user_name=user_name,
                email=email,
                timestamp=timestamp,
            )

            self.refresh_cards()

            if isinstance(result, tuple):
                public_entry, private_entry = result
                self.show_entry_details(private_entry, "private")

                QMessageBox.information(
                    self,
                    "Import Successful",
                    "Key pair has been imported successfully.",
                )
            else:
                public_entry = result
                self.show_entry_details(public_entry, "public")

                QMessageBox.information(
                    self,
                    "Import Successful",
                    "Public key has been imported successfully.",
                )

        except Exception as e:
            if "Keyring password is required" in str(e):
                password, ok = QInputDialog.getText(
                    self,
                    "Protect Imported Private Key",
                    "Enter keyring password for imported private key:",
                    QLineEdit.EchoMode.Password,
                )

                if not ok:
                    return

                try:
                    result = keyring_services.import_key(
                        file_path=file_path,
                        user_name=user_name,
                        email=email,
                        timestamp=timestamp,
                        keyring_password=password,
                    )

                    self.refresh_cards()

                    if isinstance(result, tuple):
                        public_entry, private_entry = result
                        self.show_entry_details(private_entry, "private")

                        QMessageBox.information(
                            self,
                            "Import Successful",
                            "Key pair has been imported successfully.",
                        )
                    else:
                        public_entry = result
                        self.show_entry_details(public_entry, "public")

                        QMessageBox.information(
                            self,
                            "Import Successful",
                            "Public key has been imported successfully.",
                        )

                except Exception as retry_error:
                    QMessageBox.critical(
                        self,
                        "Import Failed",
                        str(retry_error),
                    )

                return

            QMessageBox.critical(
                self,
                "Import Failed",
                str(e),
            )

    def on_export_clicked(self):
        if self.selected_entry is None:
            QMessageBox.warning(self, "No Key Selected", "Please select a key first.")
            return

        key_id = self.selected_entry["key_id"]

        if self.selected_key_type == "public":
            include_metadata = self.ask_include_metadata()

            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Public Key",
                f"{key_id}_public.pem",
                "PEM Files (*.pem);;All Files (*)",
            )

            if not file_path:
                return

            try:
                keyring_services.export_public_key(
                    key_id,
                    file_path,
                    include_metadata=include_metadata,
                )

                QMessageBox.information(
                    self,
                    "Export Successful",
                    "Public key has been exported successfully.",
                )

            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Export Failed",
                    str(e),
                )

            return

        if self.selected_key_type == "private":
            include_metadata = self.ask_include_metadata()

            # password, ok = QInputDialog.getText(
            #     self,
            #     "Unlock Private Key",
            #     "Enter private key password:",
            #     QLineEdit.EchoMode.Password,
            # )

            # if not ok:
            #     return

            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Key Pair",
                f"{key_id}_key_pair.pem",
                "PEM Files (*.pem);;All Files (*)",
            )

            if not file_path:
                return

            try:
                keyring_services.export_key_pair(
                    key_id=key_id,
                    unlock_password=None,
                    file_path=file_path,
                    include_metadata=include_metadata,
                )

                QMessageBox.information(
                    self,
                    "Export Successful",
                    "Key pair has been exported successfully.",
                )

            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Export Failed",
                    str(e),
                )

    def ask_include_metadata(self):
        answer = QMessageBox.question(
            self,
            "Export Metadata",
            "Do you want to include key owner metadata (name, email, timestamp) in the PEM file?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )

        return answer == QMessageBox.StandardButton.Yes

    def extract_key_file_metadata(self, file_path: str):
        try:
            content = Path(file_path).read_text(encoding="utf-8")
        except Exception:
            return {}

        if METADATA_BEGIN not in content or METADATA_END not in content:
            return {}

        start = content.find(METADATA_BEGIN) + len(METADATA_BEGIN)
        end = content.find(METADATA_END, start)

        if end == -1:
            return {}

        metadata = {}
        key_map = {
            "User-Name": "user_name",
            "Email": "email",
            "Timestamp": "timestamp",
            "Key-ID": "key_id",
        }

        for raw_line in content[start:end].splitlines():
            line = raw_line.strip()

            if line.startswith("#"):
                line = line[1:].strip()

            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            normalized_key = key_map.get(key.strip())

            if normalized_key:
                metadata[normalized_key] = value.strip()

        return metadata

    def metadata_timestamp(self, metadata: dict):
        timestamp = metadata.get("timestamp")

        if timestamp is None:
            return None

        try:
            return int(float(timestamp))
        except (TypeError, ValueError):
            return None

    def on_delete_clicked(self):
        if self.selected_entry is None:
            QMessageBox.warning(
                self,
                "No Key Selected",
                "Please select a key first.",
            )
            return

        key_id = self.selected_entry["key_id"]

        if self.selected_key_type == "public":
            answer = QMessageBox.question(
                self,
                "Delete Public Key",
                "Are you sure you want to delete this public key?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if answer != QMessageBox.StandardButton.Yes:
                return

            try:
                deleted = keyring_services.delete_public_key(key_id)

                if not deleted:
                    QMessageBox.warning(
                        self,
                        "Delete Failed",
                        "Public key was not found.",
                    )
                    return

                self.refresh_cards()
                self.reset_details_panel()

                QMessageBox.information(
                    self,
                    "Delete Successful",
                    "Public key has been deleted successfully.",
                )

            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Delete Failed",
                    str(e),
                )

            return

        if self.selected_key_type == "private":
            answer = QMessageBox.question(
                self,
                "Delete Private Key",
                "Do you also want to delete the matching public key?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )

            if answer == QMessageBox.StandardButton.Cancel:
                return

            delete_public_key_entry = answer == QMessageBox.StandardButton.Yes

            try:
                deleted = keyring_services.delete_private_key(
                    key_id,
                    delete_public_key_entry=delete_public_key_entry,
                )

                if not deleted:
                    QMessageBox.warning(
                        self,
                        "Delete Failed",
                        "Private key was not found.",
                    )
                    return

                self.refresh_cards()
                self.reset_details_panel()

                if delete_public_key_entry:
                    message = "Private key and matching public key have been deleted successfully."
                else:
                    message = "Private key has been deleted successfully."

                QMessageBox.information(
                    self,
                    "Delete Successful",
                    message,
                )

            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Delete Failed",
                    str(e),
                )
