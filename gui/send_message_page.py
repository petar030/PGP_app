from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt


class SendMessagePage(QWidget):
    def __init__(self):
        super().__init__()

        title = QLabel("Send Message")
        title.setObjectName("PageTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addStretch()

        self.setLayout(layout)