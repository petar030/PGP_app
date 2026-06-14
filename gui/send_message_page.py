from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from api.auth_services import create_message_component, sign_message
from api.compression_utils import compress_data
from api.encryption_services import SUPPORTED_CIPHERS, encrypt_message
from api.output_utils import encode_radix64, serialize_final_packet
import rsa_keyring.keyring_services as keyring_services


class SendMessagePage(QWidget):
    INPUT_PAGE = 0
    SIGN_QUESTION_PAGE = 1
    SIGN_DETAILS_PAGE = 2
    COMPRESSION_QUESTION_PAGE = 3
    ENCRYPTION_QUESTION_PAGE = 4
    ENCRYPTION_DETAILS_PAGE = 5
    RADIX_QUESTION_PAGE = 6
    SUMMARY_PAGE = 7

    def __init__(self):
        super().__init__()

        keyring_services.initialize_keyrings()

        self.flow_state = self.default_flow_state()
        self.history = []

        title = QLabel("Send Message")
        title.setObjectName("PageTitle")

        self.step_label = QLabel("")
        self.step_label.setObjectName("FlowStepLabel")

        self.stack = QStackedWidget()
        self.stack.addWidget(self.create_input_page())
        self.stack.addWidget(self.create_sign_question_page())
        self.stack.addWidget(self.create_sign_details_page())
        self.stack.addWidget(self.create_compression_question_page())
        self.stack.addWidget(self.create_encryption_question_page())
        self.stack.addWidget(self.create_encryption_details_page())
        self.stack.addWidget(self.create_radix_question_page())
        self.stack.addWidget(self.create_summary_page())

        self.back_button = QPushButton("Back")
        self.next_button = QPushButton("Next")
        self.restart_button = QPushButton("New Message")
        self.refresh_keys_button = QPushButton("Refresh Keys")
        self.create_file_button = QPushButton("Create Message File")

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.refresh_keys_button)
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.restart_button)
        buttons_layout.addWidget(self.back_button)
        buttons_layout.addWidget(self.next_button)
        buttons_layout.addWidget(self.create_file_button)

        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)
        root_layout.addWidget(title)
        root_layout.addWidget(self.step_label)
        root_layout.addWidget(self.stack, stretch=1)
        root_layout.addLayout(buttons_layout)

        self.setLayout(root_layout)

        self.apply_local_styles()
        self.refresh_key_lists()
        self.show_page(self.INPUT_PAGE, record_history=False)

        self.back_button.clicked.connect(self.on_back_clicked)
        self.next_button.clicked.connect(self.on_next_clicked)
        self.restart_button.clicked.connect(self.on_restart_clicked)
        self.refresh_keys_button.clicked.connect(self.refresh_key_lists)
        self.create_file_button.clicked.connect(self.on_create_file_clicked)

    def default_flow_state(self):
        return {
            "data": "",
            "filename": "",
            "sign": False,
            "signing_key_id": None,
            "signing_password": "",
            "compress": False,
            "encrypt": False,
            "receiver_key_id": None,
            "symmetric_algo": "AES128",
            "radix": False,
        }

    def create_input_page(self):
        self.message_input = QPlainTextEdit()
        self.message_input.setPlaceholderText("Message text")
        self.message_input.setMinimumHeight(260)

        self.filename_input = QLineEdit()
        self.filename_input.setPlaceholderText("message_name")

        form_layout = QFormLayout()
        form_layout.addRow("Filename:", self.filename_input)
        form_layout.addRow("Data:", self.message_input)

        group = QGroupBox("Input data and filename")
        group.setLayout(form_layout)

        return self.wrap_page(group)

    def create_sign_question_page(self):
        return self.create_question_page(
            "Do you want to sign the message?",
            self.on_sign_yes,
            self.on_sign_no,
        )

    def create_sign_details_page(self):
        self.sign_key_combo = QComboBox()

        self.sign_password_input = QLineEdit()
        self.sign_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout = QFormLayout()
        form_layout.addRow("Private key:", self.sign_key_combo)
        form_layout.addRow("Private key password:", self.sign_password_input)

        group = QGroupBox("Choose signing key")
        group.setLayout(form_layout)

        return self.wrap_page(group)

    def create_compression_question_page(self):
        return self.create_question_page(
            "Do you want to compress the packet?",
            self.on_compress_yes,
            self.on_compress_no,
        )

    def create_encryption_question_page(self):
        return self.create_question_page(
            "Do you want to encrypt the message?",
            self.on_encrypt_yes,
            self.on_encrypt_no,
        )

    def create_encryption_details_page(self):
        self.encrypt_key_combo = QComboBox()
        self.symmetric_algo_combo = QComboBox()

        for algorithm in SUPPORTED_CIPHERS:
            self.symmetric_algo_combo.addItem(algorithm, algorithm)

        form_layout = QFormLayout()
        form_layout.addRow("Recipient public key:", self.encrypt_key_combo)
        form_layout.addRow("Symmetric algorithm:", self.symmetric_algo_combo)

        group = QGroupBox("Choose encryption settings")
        group.setLayout(form_layout)

        return self.wrap_page(group)

    def create_radix_question_page(self):
        return self.create_question_page(
            "Do you want Radix-64 ASCII armor?",
            self.on_radix_yes,
            self.on_radix_no,
        )

    def create_summary_page(self):
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("FlowSummary")
        self.summary_label.setWordWrap(True)
        self.summary_label.setAlignment(Qt.AlignmentFlag.AlignTop)

        group = QGroupBox("Ready to create file")
        layout = QVBoxLayout()
        layout.addWidget(self.summary_label)
        layout.addStretch()
        group.setLayout(layout)

        return self.wrap_page(group)

    def create_question_page(self, question: str, yes_handler, no_handler):
        question_label = QLabel(question)
        question_label.setObjectName("FlowQuestion")
        question_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        question_label.setWordWrap(True)

        yes_button = QPushButton("Yes")
        no_button = QPushButton("No")
        yes_button.setMinimumWidth(120)
        no_button.setMinimumWidth(120)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        buttons_layout.addWidget(yes_button)
        buttons_layout.addWidget(no_button)
        buttons_layout.addStretch()

        card = QFrame()
        card.setObjectName("FlowQuestionCard")
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(18)
        layout.addStretch()
        layout.addWidget(question_label)
        layout.addLayout(buttons_layout)
        layout.addStretch()
        card.setLayout(layout)

        yes_button.clicked.connect(yes_handler)
        no_button.clicked.connect(no_handler)

        return self.wrap_page(card)

    def wrap_page(self, content_widget):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(content_widget)
        page.setLayout(layout)
        return page

    def refresh_key_lists(self):
        self.populate_key_combo(self.sign_key_combo, keyring_services.get_private_keys())
        self.populate_key_combo(self.encrypt_key_combo, keyring_services.get_public_keys())

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

    def show_page(self, page_index: int, record_history: bool = True):
        current_index = self.stack.currentIndex()

        if record_history and current_index != page_index:
            self.history.append(current_index)

        if page_index == self.SUMMARY_PAGE:
            self.update_summary()

        self.stack.setCurrentIndex(page_index)
        self.update_navigation()

    def update_navigation(self):
        page_index = self.stack.currentIndex()

        step_names = {
            self.INPUT_PAGE: "Step 1: Message",
            self.SIGN_QUESTION_PAGE: "Step 2: Signature",
            self.SIGN_DETAILS_PAGE: "Step 3: Signing key",
            self.COMPRESSION_QUESTION_PAGE: "Step 4: Compression",
            self.ENCRYPTION_QUESTION_PAGE: "Step 5: Encryption",
            self.ENCRYPTION_DETAILS_PAGE: "Step 6: Encryption settings",
            self.RADIX_QUESTION_PAGE: "Step 7: Output encoding",
            self.SUMMARY_PAGE: "Step 8: Save",
        }

        self.step_label.setText(step_names.get(page_index, ""))
        self.back_button.setEnabled(bool(self.history))
        self.restart_button.setEnabled(page_index != self.INPUT_PAGE or bool(self.history))
        self.next_button.setVisible(page_index in (self.INPUT_PAGE, self.SIGN_DETAILS_PAGE, self.ENCRYPTION_DETAILS_PAGE))
        self.create_file_button.setVisible(page_index == self.SUMMARY_PAGE)

    def on_next_clicked(self):
        page_index = self.stack.currentIndex()

        if page_index == self.INPUT_PAGE:
            if not self.capture_input_data():
                return

            self.show_page(self.SIGN_QUESTION_PAGE)
            return

        if page_index == self.SIGN_DETAILS_PAGE:
            if not self.capture_sign_details():
                return

            self.show_page(self.COMPRESSION_QUESTION_PAGE)
            return

        if page_index == self.ENCRYPTION_DETAILS_PAGE:
            if not self.capture_encryption_details():
                return

            self.show_page(self.RADIX_QUESTION_PAGE)

    def on_back_clicked(self):
        if not self.history:
            return

        previous_page = self.history.pop()
        self.show_page(previous_page, record_history=False)

    def on_restart_clicked(self):
        self.flow_state = self.default_flow_state()
        self.history = []
        self.message_input.clear()
        self.filename_input.clear()
        self.sign_password_input.clear()
        self.show_page(self.INPUT_PAGE, record_history=False)

    def capture_input_data(self):
        filename = self.filename_input.text().strip()

        if not filename:
            QMessageBox.warning(self, "Missing Filename", "Please enter a filename.")
            return False

        self.flow_state["filename"] = filename
        self.flow_state["data"] = self.message_input.toPlainText()

        return True

    def capture_sign_details(self):
        signing_key_id = self.sign_key_combo.currentData()
        signing_password = self.sign_password_input.text()

        if signing_key_id is None:
            QMessageBox.warning(self, "Missing Signing Key", "Please choose a private key.")
            return False

        if not signing_password:
            QMessageBox.warning(self, "Missing Password", "Please enter the private key password.")
            return False

        try:
            keyring_services.unlock_private_key(signing_key_id, signing_password)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Private Key Unlock Failed",
                f"Private key could not be unlocked: {e}",
            )
            return False

        self.flow_state["signing_key_id"] = signing_key_id
        self.flow_state["signing_password"] = signing_password

        return True

    def capture_encryption_details(self):
        receiver_key_id = self.encrypt_key_combo.currentData()

        if receiver_key_id is None:
            QMessageBox.warning(self, "Missing Encryption Key", "Please choose a public key.")
            return False

        self.flow_state["receiver_key_id"] = receiver_key_id
        self.flow_state["symmetric_algo"] = self.symmetric_algo_combo.currentData()

        return True

    def on_sign_yes(self):
        self.flow_state["sign"] = True
        self.show_page(self.SIGN_DETAILS_PAGE)

    def on_sign_no(self):
        self.flow_state["sign"] = False
        self.flow_state["signing_key_id"] = None
        self.flow_state["signing_password"] = ""
        self.sign_password_input.clear()
        self.show_page(self.COMPRESSION_QUESTION_PAGE)

    def on_compress_yes(self):
        self.flow_state["compress"] = True
        self.show_page(self.ENCRYPTION_QUESTION_PAGE)

    def on_compress_no(self):
        self.flow_state["compress"] = False
        self.show_page(self.ENCRYPTION_QUESTION_PAGE)

    def on_encrypt_yes(self):
        self.flow_state["encrypt"] = True
        self.show_page(self.ENCRYPTION_DETAILS_PAGE)

    def on_encrypt_no(self):
        self.flow_state["encrypt"] = False
        self.flow_state["receiver_key_id"] = None
        self.flow_state["symmetric_algo"] = "AES128"
        self.show_page(self.RADIX_QUESTION_PAGE)

    def on_radix_yes(self):
        self.flow_state["radix"] = True
        self.show_page(self.SUMMARY_PAGE)

    def on_radix_no(self):
        self.flow_state["radix"] = False
        self.show_page(self.SUMMARY_PAGE)

    def update_summary(self):
        lines = [
            f"Filename: {self.flow_state['filename']}",
            f"Sign: {self.format_bool(self.flow_state['sign'])}",
            f"Compress: {self.format_bool(self.flow_state['compress'])}",
            f"Encrypt: {self.format_bool(self.flow_state['encrypt'])}",
            f"Radix-64: {self.format_bool(self.flow_state['radix'])}",
        ]

        if self.flow_state["sign"]:
            lines.insert(2, f"Signing key: {self.flow_state['signing_key_id']}")

        if self.flow_state["encrypt"]:
            lines.insert(-1, f"Recipient key: {self.flow_state['receiver_key_id']}")
            lines.insert(-1, f"Symmetric algorithm: {self.flow_state['symmetric_algo']}")

        self.summary_label.setText("\n".join(lines))

    def format_bool(self, value: bool):
        return "Yes" if value else "No"

    def on_create_file_clicked(self):
        default_output_name = f"{Path(self.flow_state['filename']).name}.asc" if self.flow_state["radix"] else f"{Path(self.flow_state['filename']).name}.pgp"
        file_filter = "ASCII Armored PGP (*.asc);;All Files (*)" if self.flow_state["radix"] else "PGP Binary (*.pgp);;All Files (*)"

        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Message",
            default_output_name,
            file_filter,
        )

        if not output_path:
            return

        try:
            output = self.build_message_output()
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

    def build_message_output(self) -> bytes | str:
        message_component = create_message_component(
            self.flow_state["data"],
            self.flow_state["filename"],
        )

        if self.flow_state["sign"]:
            private_key = keyring_services.unlock_private_key(
                self.flow_state["signing_key_id"],
                self.flow_state["signing_password"],
            )
            packet = sign_message(
                message_component,
                private_key,
                self.flow_state["signing_key_id"],
            )
        else:
            packet = message_component

        compressed_bytes = compress_data(
            packet,
            is_signed=self.flow_state["sign"],
            perform_compression=self.flow_state["compress"],
        )

        if self.flow_state["encrypt"]:
            receiver_public_key = keyring_services.get_public_key_object(
                self.flow_state["receiver_key_id"],
            )
            data_dict = encrypt_message(
                compressed_bytes,
                receiver_public_key,
                self.flow_state["receiver_key_id"],
                self.flow_state["symmetric_algo"],
            )
        else:
            data_dict = {"data": compressed_bytes}

        serialized_packet = serialize_final_packet(data_dict, self.flow_state["encrypt"])

        if self.flow_state["radix"]:
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

        #FlowStepLabel {
            background-color: transparent;
            color: #b8b08a;
            font-weight: bold;
        }

        #FlowQuestionCard {
            background-color: #1b2228;
            border: 1px solid #26313a;
            border-radius: 6px;
        }

        #FlowQuestion {
            background-color: transparent;
            color: #ffffff;
            font-size: 18px;
            font-weight: bold;
        }

        #FlowSummary {
            background-color: transparent;
            color: #e6e6e6;
            font-size: 14px;
            line-height: 1.4;
        }
        """)
