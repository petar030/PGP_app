from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
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
    QVBoxLayout,
    QWidget,
)

from api.auth_services import create_message_component, sign_message
from api.compression_utils import compress_data
from api.encryption_services import SUPPORTED_CIPHERS, encrypt_message
from api.output_utils import encode_radix64, serialize_final_packet
import rsa_keyring.keyring_services as keyring_services


class SendMessagePage(QWidget):
    def __init__(self):
        super().__init__()

        keyring_services.initialize_keyrings()

        title = QLabel("Send Message")
        title.setObjectName("PageTitle")

        self.message_input = QPlainTextEdit()
        self.message_input.setPlaceholderText("Message text")
        self.message_input.setMinimumHeight(190)

        self.filename_input = QLineEdit()
        self.filename_input.setPlaceholderText("message.txt")

        message_form = QFormLayout()
        message_form.addRow("Filename:", self.filename_input)
        message_form.addRow("Data:", self.message_input)

        message_group = QGroupBox("Input")
        message_group.setLayout(message_form)

        self.sign_checkbox = QCheckBox("Sign")
        self.compress_checkbox = QCheckBox("Compress")
        self.encrypt_checkbox = QCheckBox("Encrypt")
        self.radix_checkbox = QCheckBox("Radix-64")

        self.sign_key_combo = QComboBox()
        self.sign_password_input = QLineEdit()
        self.sign_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.encrypt_key_combo = QComboBox()
        self.symmetric_algo_combo = QComboBox()

        for algorithm in SUPPORTED_CIPHERS:
            self.symmetric_algo_combo.addItem(algorithm, algorithm)

        options_form = QFormLayout()
        options_form.addRow("", self.sign_checkbox)
        options_form.addRow("Private key:", self.sign_key_combo)
        options_form.addRow("Private key password:", self.sign_password_input)
        options_form.addRow("", self.compress_checkbox)
        options_form.addRow("", self.encrypt_checkbox)
        options_form.addRow("Recipient public key:", self.encrypt_key_combo)
        options_form.addRow("Symmetric algorithm:", self.symmetric_algo_combo)
        options_form.addRow("", self.radix_checkbox)

        options_group = QGroupBox("Processing")
        options_group.setLayout(options_form)

        self.refresh_keys_button = QPushButton("Refresh Keys")
        self.send_button = QPushButton("Create Message File")

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.refresh_keys_button)
        buttons_layout.addWidget(self.send_button)

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)
        root_layout.addWidget(title)
        root_layout.addWidget(message_group)
        root_layout.addWidget(options_group)
        root_layout.addLayout(buttons_layout)
        root_layout.addStretch()

        self.setLayout(root_layout)

        self.apply_local_styles()
        self.refresh_key_lists()
        self.update_option_states()

        self.sign_checkbox.toggled.connect(self.update_option_states)
        self.encrypt_checkbox.toggled.connect(self.update_option_states)
        self.refresh_keys_button.clicked.connect(self.refresh_key_lists)
        self.send_button.clicked.connect(self.on_create_message_clicked)

    def refresh_key_lists(self):
        self.populate_key_combo(self.sign_key_combo, keyring_services.get_private_keys())
        self.populate_key_combo(self.encrypt_key_combo, keyring_services.get_public_keys())
        self.update_option_states()

    def populate_key_combo(self, combo: QComboBox, keys: list[dict]):
        current_key_id = combo.currentData()

        combo.blockSignals(True)
        combo.clear()

        for entry in keys:
            key_id = entry.get("key_id", "")
            owner = self.format_key_owner(entry)
            combo.addItem(f"{owner} ({key_id})", key_id)

        if current_key_id:
            index = combo.findData(current_key_id)
            if index >= 0:
                combo.setCurrentIndex(index)

        combo.blockSignals(False)

    def format_key_owner(self, entry: dict) -> str:
        name = entry.get("user_name", "").strip()
        email = entry.get("email", "").strip()

        if name and email:
            return f"{name} <{email}>"

        return name or email or "Unnamed key"

    def update_option_states(self):
        signing = self.sign_checkbox.isChecked()
        encrypting = self.encrypt_checkbox.isChecked()

        self.sign_key_combo.setEnabled(signing)
        self.sign_password_input.setEnabled(signing)
        self.encrypt_key_combo.setEnabled(encrypting)
        self.symmetric_algo_combo.setEnabled(encrypting)

    def on_create_message_clicked(self):
        data = self.message_input.toPlainText()
        filename = self.filename_input.text().strip()

        if not filename:
            QMessageBox.warning(self, "Missing Filename", "Please enter a filename.")
            return

        if self.sign_checkbox.isChecked() and self.sign_key_combo.currentData() is None:
            QMessageBox.warning(self, "Missing Signing Key", "Please choose a private key.")
            return

        if self.encrypt_checkbox.isChecked() and self.encrypt_key_combo.currentData() is None:
            QMessageBox.warning(self, "Missing Encryption Key", "Please choose a public key.")
            return

        default_output_name = f"{Path(filename).name}.asc" if self.radix_checkbox.isChecked() else f"{Path(filename).name}.pgp"
        file_filter = "ASCII Armored PGP (*.asc);;All Files (*)" if self.radix_checkbox.isChecked() else "PGP Binary (*.pgp);;All Files (*)"

        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Message",
            default_output_name,
            file_filter,
        )

        if not output_path:
            return

        try:
            output = self.build_message_output(data, filename)
            path = Path(output_path)

            if isinstance(output, str):
                path.write_text(output, encoding="utf-8")
            else:
                path.write_bytes(output)

            QMessageBox.information(
                self,
                "Message Created",
                "Message file has been created successfully.",
            )

        except Exception as e:
            QMessageBox.critical(self, "Message Creation Failed", str(e))

    def build_message_output(self, data: str, filename: str) -> bytes | str:
        message_component = create_message_component(data, filename)
        is_signed = self.sign_checkbox.isChecked()

        if is_signed:
            signing_key_id = self.sign_key_combo.currentData()
            signing_password = self.sign_password_input.text()

            if not signing_password:
                raise ValueError("Private key password is required for signing.")

            private_key = keyring_services.unlock_private_key(
                signing_key_id,
                signing_password,
            )
            packet = sign_message(message_component, private_key, signing_key_id)
        else:
            packet = message_component

        compressed_bytes = compress_data(
            packet,
            is_signed=is_signed,
            perform_compression=self.compress_checkbox.isChecked(),
        )

        is_encrypted = self.encrypt_checkbox.isChecked()

        if is_encrypted:
            receiver_key_id = self.encrypt_key_combo.currentData()
            receiver_public_key = keyring_services.get_public_key_object(receiver_key_id)
            symmetric_algo = self.symmetric_algo_combo.currentData()
            data_dict = encrypt_message(
                compressed_bytes,
                receiver_public_key,
                receiver_key_id,
                symmetric_algo,
            )
        else:
            data_dict = {"data": compressed_bytes}

        serialized_packet = serialize_final_packet(data_dict, is_encrypted)

        if self.radix_checkbox.isChecked():
            return encode_radix64(serialized_packet)

        return serialized_packet

    def apply_local_styles(self):
        self.setStyleSheet("""
        QLineEdit,
        QPlainTextEdit,
        QComboBox {
            background-color: #202830;
            border: 1px solid #4d5962;
            border-radius: 5px;
            padding: 6px;
            color: #ffffff;
        }

        QPlainTextEdit {
            selection-background-color: #3a5369;
        }

        QCheckBox {
            spacing: 8px;
        }

        QCheckBox::indicator {
            width: 15px;
            height: 15px;
        }

        QCheckBox::indicator:unchecked {
            background-color: #202830;
            border: 1px solid #4d5962;
            border-radius: 3px;
        }

        QCheckBox::indicator:checked {
            background-color: #b8b08a;
            border: 1px solid #d6cfa5;
            border-radius: 3px;
        }
        """)
