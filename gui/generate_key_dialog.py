from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


class GenerateKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Generate New Key Pair")
        self.setModal(True)
        self.setMinimumWidth(380)

        self.name_input = QLineEdit()
        self.email_input = QLineEdit()

        self.key_size_input = QComboBox()
        self.key_size_input.addItem("1024", 1024)
        self.key_size_input.addItem("2048", 2048)
        self.key_size_input.setCurrentIndex(1)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.error_label = QLabel("")
        self.error_label.setObjectName("DialogError")

        form_layout = QFormLayout()
        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Email:", self.email_input)
        form_layout.addRow("Key Size:", self.key_size_input)
        form_layout.addRow("Password:", self.password_input)
        form_layout.addRow("Confirm Password:", self.confirm_password_input)

        self.cancel_button = QPushButton("Cancel")
        self.generate_button = QPushButton("Generate")

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.cancel_button)
        buttons_layout.addWidget(self.generate_button)

        root_layout = QVBoxLayout()
        root_layout.addLayout(form_layout)
        root_layout.addWidget(self.error_label)
        root_layout.addLayout(buttons_layout)

        self.setLayout(root_layout)

        self.cancel_button.clicked.connect(self.reject)
        self.generate_button.clicked.connect(self.validate_and_accept)

        self.setStyleSheet("""
        QDialog {
            background-color: #171d22;
            color: #e6e6e6;
            font-family: Arial;
            font-size: 13px;
        }

        QLineEdit,
        QComboBox {
            background-color: #202830;
            border: 1px solid #4d5962;
            border-radius: 5px;
            padding: 6px;
            color: #ffffff;
        }

        QPushButton {
            background-color: #303941;
            border: 1px solid #4d5962;
            border-radius: 5px;
            padding: 8px 12px;
            color: white;
        }

        QPushButton:hover {
            background-color: #3d4852;
        }

        #DialogError {
            color: #ff7777;
            padding-top: 4px;
        }
        """)

    def validate_and_accept(self):
        name = self.name_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not name:
            self.error_label.setText("Name is required.")
            return

        if not email:
            self.error_label.setText("Email is required.")
            return

        if not password:
            self.error_label.setText("Password is required.")
            return

        if password != confirm_password:
            self.error_label.setText("Passwords do not match.")
            return

        self.accept()

    def get_data(self):
        return {
            "user_name": self.name_input.text().strip(),
            "email": self.email_input.text().strip(),
            "key_size": self.key_size_input.currentData(),
            "password": self.password_input.text(),
        }
