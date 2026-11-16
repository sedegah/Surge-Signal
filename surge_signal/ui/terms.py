"""First-launch Terms and Conditions dialog."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)

from ..core.branding import APP_NAME, APP_VERSION
from ..core.config import Settings
from ..core.domain import iso_now


TERMS_HTML = """
<style>
body { color: #d8d8d8; font-family: 'Segoe UI'; font-size: 12px; line-height: 1.55; }
h2 { color: #ffffff; font-size: 15px; margin: 18px 0 6px 0; }
h3 { color: #f26a21; font-size: 12px; margin: 14px 0 4px 0; }
p { margin: 0 0 8px 0; }
li { margin: 0 0 4px 0; }
.note { background: #2b2b30; border-left: 3px solid #f26a21; padding: 9px 12px; }
</style>

<h2>SURGE Signal Terms and Conditions</h2>
<p><b>Version 1.0.0</b></p>

<div class="note">
Use SURGE Signal only on Wi-Fi networks, devices and capture files that you own
or have explicit written permission to assess. You are responsible for confirming
that you have that permission before scanning, recording or testing.
</div>

<h3>1. Authorised use</h3>
<p>
You may use this software for lawful wireless security assessment, education and
defensive testing. You must not use it to access, disrupt, monitor or test a network
without permission from the network owner.
</p>

<h3>2. Password testing</h3>
<p>
Password testing is an offline check against a capture you are authorised to hold.
It must be used only on your own network or an explicitly authorised laboratory
network. Do not use recovered credentials to access systems or data you are not
authorised to use.
</p>

<h3>3. No disruption</h3>
<p>
The application is designed for passive discovery and passive capture. It does not
send deauthentication frames, create rogue access points or inject packets. You must
not modify or extend it to disrupt networks or devices.
</p>

<h3>4. Your data</h3>
<p>
Assessments, captures, reports and password lists are stored locally on your
computer. You are responsible for protecting that data, keeping backups and
following any confidentiality or retention rules that apply to your work.
</p>

<h3>5. No warranty</h3>
<p>
The software is provided “as is” without warranties of any kind. Wireless security
results can be incomplete or affected by hardware, drivers, radio conditions and
capture quality. You must review every result before relying on it.
</p>

<h3>6. Limitation of liability</h3>
<p>
To the maximum extent permitted by law, the authors are not liable for loss, damage,
service disruption, data loss or legal consequences arising from misuse of the
software or from testing without authorisation.
</p>

<h3>7. Privacy</h3>
<p>
The application does not require an account and does not send assessment data to a
remote service. Linux credentials are requested only for privileged local commands
and are not stored by SURGE Signal.
</p>

<h3>8. Changes</h3>
<p>
These terms may be updated with future releases. A new acceptance is requested when
the terms version changes.
</p>

<h2>Acceptance</h2>
<p>
By selecting “Accept and continue”, you confirm that you have read and agree to
these terms and that you will use SURGE Signal only for authorised purposes.
</p>
"""


def terms_accepted(settings: Settings) -> bool:
    return settings.get("terms_accepted_version", "") == APP_VERSION


class TermsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle(f"Terms and Conditions — {APP_NAME}")
        self.setModal(True)
        self.setMinimumSize(760, 650)
        self.resize(820, 700)
        self.setObjectName("TermsDialog")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 16)
        outer.setSpacing(10)

        title = QLabel("Terms and Conditions")
        title.setProperty("role", "h1")
        outer.addWidget(title)
        subtitle = QLabel(
            f"{APP_NAME} {APP_VERSION}  ·  Please read before using the application."
        )
        subtitle.setProperty("role", "muted")
        outer.addWidget(subtitle)

        self.text = QTextBrowser()
        self.text.setOpenExternalLinks(False)
        self.text.setHtml(TERMS_HTML)
        self.text.setStyleSheet(
            "QTextBrowser{background:#1e1e1e;color:#d8d8d8;border:1px solid #4a4a50;"
            "padding:10px;}"
        )
        outer.addWidget(self.text, 1)

        self.agree = QCheckBox(
            "I have read and agree to the Terms and Conditions and the authorised-use policy."
        )
        self.agree.toggled.connect(self._toggle_accept)
        outer.addWidget(self.agree)

        actions = QHBoxLayout()
        actions.addStretch(1)
        decline = QPushButton("Decline and exit")
        decline.clicked.connect(self.reject)
        actions.addWidget(decline)
        self.accept_button = QPushButton("Accept and continue")
        self.accept_button.setProperty("variant", "primary")
        self.accept_button.setEnabled(False)
        self.accept_button.clicked.connect(self._accept)
        actions.addWidget(self.accept_button)
        outer.addLayout(actions)

    def _toggle_accept(self, checked: bool) -> None:
        self.accept_button.setEnabled(checked)

    def _accept(self) -> None:
        self.settings.set("terms_accepted_version", APP_VERSION)
        self.settings.set("terms_accepted_at", iso_now())
        self.accept()
