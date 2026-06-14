from pathlib import Path
from html import escape

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from api.auth_services import extract_message_component, verify_signature
from api.compression_utils import decompress_data
from api.encryption_services import decrypt_message
from api.output_utils import PGP_BEGIN, decode_radix64, deserialize_final_packet
import rsa_keyring.keyring_services as keyring_services


class ReceiveMessagePage(QWidget):
    def __init__(self):
        super().__init__()

        keyring_services.initialize_keyrings()

        self.serialized_packet = None
        self.final_packet = None
        self.encrypted_packet = None
        self.decrypted_payload = None
        self.extracted_message = None
        self.status = {}

        title = QLabel("Receive Message")
        title.setObjectName("PageTitle")

        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Choose .pgp or .asc message")

        self.browse_button = QPushButton("Browse")
        self.process_button = QPushButton("Process Message")
        self.save_message_button = QPushButton("Save Original Message")
        self.reset_button = QPushButton("Reset")

        file_row = QHBoxLayout()
        file_row.addWidget(self.file_path_input, stretch=1)
        file_row.addWidget(self.browse_button)

        file_group = QGroupBox("Input file")
        file_layout = QVBoxLayout()
        file_layout.addLayout(file_row)
        file_layout.addWidget(self.process_button)
        file_group.setLayout(file_layout)

        self.receiver_key_combo = QComboBox()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.decrypt_button = QPushButton("Unlock and Continue")

        decrypt_form = QFormLayout()
        decrypt_form.addRow("Private key:", self.receiver_key_combo)
        decrypt_form.addRow("Private key password:", self.password_input)

        decrypt_layout = QVBoxLayout()
        decrypt_layout.addLayout(decrypt_form)
        decrypt_layout.addWidget(self.decrypt_button)

        self.decrypt_group = QGroupBox("Decryption required")
        self.decrypt_group.setLayout(decrypt_layout)
        self.decrypt_group.setVisible(False)

        self.status_output = QTextEdit()
        self.status_output.setReadOnly(True)
        self.status_output.setMinimumHeight(210)

        status_group = QGroupBox("Current status")
        status_layout = QVBoxLayout()
        status_layout.addWidget(self.status_output)
        status_group.setLayout(status_layout)

        self.message_output = QPlainTextEdit()
        self.message_output.setReadOnly(True)
        self.message_output.setMinimumHeight(150)

        message_group = QGroupBox("Message")
        message_layout = QVBoxLayout()
        message_layout.addWidget(self.message_output)
        message_group.setLayout(message_layout)

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)
        root_layout.addWidget(title)
        root_layout.addWidget(file_group)
        root_layout.addWidget(self.decrypt_group)
        root_layout.addWidget(status_group)
        root_layout.addWidget(message_group)
        root_layout.addWidget(self.save_message_button)
        root_layout.addWidget(self.reset_button)

        self.setLayout(root_layout)

        self.apply_local_styles()
        self.refresh_private_keys()

        self.browse_button.clicked.connect(self.on_browse_clicked)
        self.process_button.clicked.connect(self.on_process_clicked)
        self.save_message_button.clicked.connect(self.on_save_message_clicked)
        self.decrypt_button.clicked.connect(self.on_decrypt_clicked)
        self.reset_button.clicked.connect(self.reset_flow)

        self.save_message_button.setEnabled(False)

    def on_browse_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Message",
            "",
            "PGP Messages (*.pgp *.asc);;All Files (*)",
        )

        if file_path:
            self.file_path_input.setText(file_path)

    def refresh_private_keys(self):
        current_key_id = self.receiver_key_combo.currentData()

        self.receiver_key_combo.blockSignals(True)
        self.receiver_key_combo.clear()

        for entry in keyring_services.get_private_keys():
            key_id = entry.get("key_id", "")
            owner = self.format_key_owner(entry)
            self.receiver_key_combo.addItem(f"{owner} ({key_id})", key_id)

        if current_key_id:
            index = self.receiver_key_combo.findData(current_key_id)
            if index >= 0:
                self.receiver_key_combo.setCurrentIndex(index)

        self.receiver_key_combo.blockSignals(False)

    def format_key_owner(self, entry: dict) -> str:
        name = entry.get("user_name", "").strip()
        email = entry.get("email", "").strip()

        if name and email:
            return f"{name} <{email}>"

        return name or email or "Unnamed key"

    def reset_flow(self):
        self.serialized_packet = None
        self.final_packet = None
        self.encrypted_packet = None
        self.decrypted_payload = None
        self.extracted_message = None
        self.status = {}
        self.password_input.clear()
        self.status_output.clear()
        self.message_output.clear()
        self.decrypt_group.setVisible(False)
        self.process_button.setEnabled(True)
        self.save_message_button.setEnabled(False)
        self.refresh_private_keys()

    def on_process_clicked(self):
        self.reset_flow()

        file_path = self.file_path_input.text().strip()

        if not file_path:
            QMessageBox.warning(self, "Missing File", "Please choose a message file.")
            return

        try:
            self.append_log_title("Start log")
            self.load_and_deserialize(file_path)

            if self.status.get("encrypted"):
                self.prepare_decryption_step()
                return

            self.decrypted_payload = self.final_packet["data"]
            self.append_status("Encryption: no")
            self.finish_packet_processing()

        except Exception as e:
            self.status["result"] = "Failed"
            self.append_status(f"Result: failed ({e})")
            self.append_log_title("End log")
            QMessageBox.critical(self, "Receive Failed", str(e))

    def load_and_deserialize(self, file_path: str):
        path = Path(file_path)

        if not path.exists():
            raise ValueError("Message file does not exist.")

        raw_bytes = path.read_bytes()
        self.status["file"] = str(path)
        self.append_status(f"File: {path.name}")

        raw_text = None

        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raw_text = None

        if raw_text is not None and raw_text.strip().startswith(PGP_BEGIN):
            self.serialized_packet = decode_radix64(raw_text)
            self.status["radix64"] = True
            self.append_status("Input format: Radix-64")
        else:
            self.serialized_packet = raw_bytes
            self.status["radix64"] = False
            self.append_status("Input format: binary")

        self.final_packet = deserialize_final_packet(self.serialized_packet)
        self.status["encrypted"] = "encrypted_data" in self.final_packet

        if self.status["encrypted"]:
            receiver_key_id = self.final_packet["receiver_key_id"]
            self.encrypted_packet = self.final_packet
            self.status["receiver_key_id"] = receiver_key_id.hex().upper()
            self.append_status(f"Encryption: yes ({self.final_packet['symmetric_algo']})")

    def prepare_decryption_step(self):
        self.refresh_private_keys()

        matching_entry = keyring_services.find_private_key(self.encrypted_packet["receiver_key_id"])

        if matching_entry is not None:
            index = self.receiver_key_combo.findData(matching_entry["key_id"])
            if index >= 0:
                self.receiver_key_combo.setCurrentIndex(index)

            self.append_status("Private key: found")
        else:
            self.status["result"] = "Failed"
            self.status["decrypted"] = False
            self.append_status("Private key: not found")
            raise ValueError("Private key for decrypting this message was not found.")

        self.decrypt_group.setVisible(True)
        self.process_button.setEnabled(False)

    def on_decrypt_clicked(self):
        key_id = self.receiver_key_combo.currentData()
        password = self.password_input.text()

        if key_id is None:
            QMessageBox.warning(self, "Missing Private Key", "Please choose a private key.")
            return

        if not password:
            QMessageBox.warning(self, "Missing Password", "Please enter the private key password.")
            return

        try:
            private_key = keyring_services.unlock_private_key(key_id, password)
            decrypted = decrypt_message(self.encrypted_packet, private_key)
            self.decrypted_payload = decrypted["decrypted_data"]
            self.status["decrypted"] = True
            self.append_status("Decryption: success")
            self.decrypt_group.setVisible(False)
            self.finish_packet_processing()

        except Exception as e:
            self.status["decrypted"] = False
            self.append_status(f"Decryption: failed ({e})")
            QMessageBox.critical(self, "Decryption Failed", str(e))

    def finish_packet_processing(self):
        packet_bytes = self.decrypted_payload

        if len(packet_bytes) < 2:
            raise ValueError("Payload is too short to contain compression/signature flags.")

        self.status["compressed"] = packet_bytes[0] == 0x01
        self.status["signed"] = packet_bytes[1] == 0x01
        self.append_status(f"Compression: {self.format_bool(self.status['compressed']).lower()}")

        packet = decompress_data(packet_bytes)

        if self.status["signed"]:
            message_component = self.verify_signed_packet(packet)
        else:
            self.status["signature"] = "Not signed"
            self.append_status("Signature: not signed")
            message_component = packet

        extracted = extract_message_component(message_component)
        self.extracted_message = extracted
        self.status["message_filename"] = extracted["filename"]
        self.status["result"] = "Success"
        self.append_status(f"Message filename: {extracted['filename']}")
        self.append_final_status()
        self.message_output.setPlainText(extracted["data"])
        self.save_message_button.setEnabled(True)

    def on_save_message_clicked(self):
        if self.extracted_message is None:
            QMessageBox.warning(self, "No Message", "There is no received message to save.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Original Message",
            self.extracted_message["filename"],
            "Text Files (*.txt);;All Files (*)",
        )

        if not file_path:
            return

        try:
            Path(file_path).write_text(self.extracted_message["data"], encoding="utf-8")
            QMessageBox.information(
                self,
                "Message Saved",
                "Original message has been saved successfully.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Save Failed", str(e))

    def verify_signed_packet(self, packet: dict):
        sender_key_id = packet["sender_key_id"]
        self.status["sender_key_id"] = sender_key_id

        sender_entry = keyring_services.find_public_key(sender_key_id)

        if sender_entry is None:
            self.append_status(f"Signature: signed by {sender_key_id}")
            self.status["signature"] = "Public key not found"
            self.status["authentication_warning"] = "Authentication was not completed because sender public key was not found."
            self.append_status("Authentication: warning, sender public key not found")
            return packet["message_comp"]

        signer = self.format_key_owner(sender_entry)
        self.status["signer"] = signer
        self.append_status(f"Signature: signed by {signer} ({sender_key_id})")

        try:
            sender_public_key = keyring_services.get_public_key_object(sender_key_id)
            verified = verify_signature(packet, sender_public_key)
            self.status["signature"] = "Valid"
            self.append_status("Authentication: success")
            return verified["message_comp"]

        except Exception as e:
            self.status["signature"] = f"Not verified ({e})"
            self.append_status(f"Authentication: failed ({e})")
            return packet["message_comp"]

    def append_final_status(self):
        self.append_log_title("End log")
        self.append_summary_line("Summary", title=True)
        self.append_summary_line(f"Result: {self.status.get('result', 'Unknown')}")
        self.append_summary_line(f"{self.format_check(self.status.get('encrypted'))} Encrypted")
        self.append_summary_line(f"{self.format_check(self.status.get('compressed'))} Compressed")
        self.append_summary_line(f"{self.format_check(self.status.get('signed'))} Signed")
        self.append_summary_line(f"Signature: {self.status.get('signature', 'Not checked')}")

        if self.status.get("signer"):
            self.append_summary_line(f"Signer: {self.status['signer']} ({self.status.get('sender_key_id')})")

        if self.status.get("authentication_warning"):
            self.append_summary_line("Warning: authentication was not successfully completed.", warning=True)

    def append_status(self, text: str):
        self.status_output.append(
            f'<div style="font-size: 12px; color: #c9d1d8; margin: 1px 0;">{escape(text)}</div>'
        )

    def append_log_title(self, text: str):
        self.status_output.append(
            f'<div style="font-size: 11px; color: #b8b08a; font-weight: bold; margin-top: 5px;">{escape(text)}</div>'
        )

    def append_summary_line(self, text: str, title: bool = False, warning: bool = False):
        if title:
            style = "font-size: 18px; color: #ffffff; font-weight: bold; margin-top: 10px;"
        elif warning:
            style = "font-size: 14px; color: #ffcc66; font-weight: bold; margin: 3px 0;"
        else:
            style = "font-size: 14px; color: #ffffff; font-weight: bold; margin: 3px 0;"

        self.status_output.append(f'<div style="{style}">{escape(text)}</div>')

    def format_bool(self, value):
        return "Yes" if bool(value) else "No"

    def format_check(self, value):
        return "✓" if bool(value) else "✗"

    def apply_local_styles(self):
        self.setStyleSheet("""
        QLineEdit,
        QPlainTextEdit,
        QTextEdit,
        QComboBox {
            background-color: #202830;
            border: 1px solid #4d5962;
            border-radius: 5px;
            padding: 6px;
            color: #ffffff;
        }

        QPlainTextEdit,
        QTextEdit {
            selection-background-color: #3a5369;
        }
        """)
