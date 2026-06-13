from PyQt6.QtWidgets import QApplication, QFrame, QHBoxLayout, QLabel, QPushButton, QStackedWidget, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt

from gui.key_management_page import KeyManagementPage
from gui.send_message_page import SendMessagePage


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PGP Cryptographic Tool")
        self.resize(1180, 650)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(150)

        self.send_button = QPushButton("✉\nSend Message")
        self.keyring_button = QPushButton("🔑\nKey Management")

        self.send_button.setObjectName("SidebarButton")
        self.keyring_button.setObjectName("SidebarButton")

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(8, 16, 8, 8)
        sidebar_layout.setSpacing(12)
        sidebar_layout.addWidget(self.send_button)
        sidebar_layout.addWidget(self.keyring_button)
        sidebar_layout.addStretch()
        self.sidebar.setLayout(sidebar_layout)

        self.stack = QStackedWidget()
        self.send_page = SendMessagePage()
        self.key_management_page = KeyManagementPage()

        self.stack.addWidget(self.send_page)
        self.stack.addWidget(self.key_management_page)

        root_layout = QHBoxLayout()
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(self.sidebar)
        root_layout.addWidget(self.stack)

        self.setLayout(root_layout)

        self.send_button.clicked.connect(lambda: self.stack.setCurrentWidget(self.send_page))
        self.keyring_button.clicked.connect(lambda: self.stack.setCurrentWidget(self.key_management_page))

        self.stack.setCurrentWidget(self.key_management_page)

        self.setStyleSheet(self.stylesheet())

    def stylesheet(self):
        return """
        QWidget {
            background-color: #171d22;
            color: #e6e6e6;
            font-family: Arial;
            font-size: 13px;
        }

        #Sidebar {
            background-color: #222b33;
            border-right: 1px solid #11161a;
        }

        #SidebarButton {
            background-color: #2c3741;
            border: 1px solid #4b5964;
            border-radius: 6px;
            padding: 12px;
            color: #f0f0f0;
            min-height: 70px;
        }

        #SidebarButton:hover {
            background-color: #3a4651;
        }

        #PageTitle {
            font-size: 22px;
            font-weight: bold;
            color: #ffffff;
        }

        QGroupBox {
            border: 1px solid #b8b08a;
            border-radius: 4px;
            margin-top: 10px;
            padding-top: 12px;
            font-weight: bold;
            color: #ffffff;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 4px;
        }

        QTableWidget {
            background-color: #151b20;
            gridline-color: #3e474f;
            border: none;
            selection-background-color: #3a5369;
            selection-color: white;
        }

        QHeaderView::section {
            background-color: #303941;
            color: white;
            padding: 6px;
            border: 1px solid #48535c;
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

        QPushButton:disabled {
            background-color: #242a30;
            color: #6f767c;
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

        #KeyCardId {
            color: #f0f0f0;
            font-weight: bold;
            font-size: 13px;
        }

        #KeyCardEmail {
            color: #d8d8d8;
            font-size: 13px;
        }

        #KeyCardName {
            color: #aeb7bf;
            font-size: 12px;
        }

        #EmptyLabel {
            color: #7f8a92;
            padding: 20px;
        }

        #DetailsPlaceholder {
            color: #7f8a92;
            font-size: 14px;
        }

        #DetailsTitle {
            font-size: 16px;
            font-weight: bold;
            color: #ffffff;
            padding-bottom: 6px;
        }

        #DetailRow {
            background-color: #1b2228;
            border-bottom: 1px solid #2e3841;
        }

        #DetailKey {
            color: #b8b08a;
            font-weight: bold;
        }

        #DetailValue {
            color: #e6e6e6;
        }
        """