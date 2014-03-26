# PyQtGPG -- Python Qt4 GPG Wrapper
# Copyright (C) 2013 KevinLi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Todo:
#[ ]GUI
#[ ]    Encryption: PyQtGPGGui.createEncryptWindow()
#[ ]        Multiple recipients
#[ ]        Symmetric cipher
#[ ]    Signing: PyQtGPGGui.createSignWindow()
#[ ]        -s --clearsign
#[ ]      		--digest-algo (if clearsign)
#[ ]Bugs:
#[ ]   Clipboard only supports text
#[ ]   Taskbar is raised after pressing any of the menu items
#
#   Note:
#     Popup balloon only allows up to six lines of text
#     Encrypt uses "--trust-model always" to bypass confirmation. See:
#       http://stackoverflow.com/a/9466566
#     GPGHandler.listKeysRegex[0] regex does not check for secondary keys;
#       Kleopatra only uses the primary public key for encryption
#     --batch in decrypt() prevents hanging in cli

import os
import sys
import re
import subprocess

from PyQt4 import QtCore, QtGui

class Clipboard(object):
    def __init__(self):
        pass

    def get(self):
        return bytes(QtGui.QApplication.clipboard().text(), "UTF-8")

    def set(self, data):
        QtGui.QApplication.clipboard().setText(data)

class GPGHandler(object):
    def __init__(self):

        self.startupinfo = None
        if os.name == "nt":
            self.startupinfo = subprocess.STARTUPINFO()
            self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        self.pubkeys = {}
        self.seckeys = {}

        self.icons = {
            "None": QtGui.QSystemTrayIcon.MessageIcon(QtGui.QSystemTrayIcon.NoIcon),
            "Info": QtGui.QSystemTrayIcon.MessageIcon(QtGui.QSystemTrayIcon.Information),
            "Warn": QtGui.QSystemTrayIcon.MessageIcon(QtGui.QSystemTrayIcon.Warning),
            "Crit": QtGui.QSystemTrayIcon.MessageIcon(QtGui.QSystemTrayIcon.Critical)
        }
        
        self.listKeysRegex = [
            re.compile(r"pub:[fmnqu-]:[\d]{4}:[\d]:([\w]{16}):[\d]{10}:(?:\d{10})?::[fmnqu-]:::(?:.*?)"),
            re.compile(r"uid:[fmnqu-]::::[\d]{10}::[\w]{40}::(.*?):"),
            re.compile(r"sec::[\d]{4}:1:([\w]{16}):[\d]{10}:(?:\d{10})?[:]{9}"),
            re.compile(r"uid:::::::[\w]{40}::(.*?):")
        ]

        self.importCheckRegex = [
            re.compile(r"(?:.*?)(?:-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----.*?-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----)+(?:.*?)", re.DOTALL),
        ]
        
        self.importRegex = [
            re.compile(r"gpg: key ([\w]{8}: .*)( not changed| imported|already in secret keyring)"),
            re.compile(r"gpg: no valid OpenPGP data found\."),
            re.compile(r"gpg: CRC error; [\w]{6} - [\w]{6}"),
            re.compile(r"gpg: (Total number processed: \d)"),
        ]

        self.decryptCheckRegex = [
            re.compile(r"(?:.*?)(?:-----BEGIN PGP MESSAGE-----.*-----END PGP MESSAGE-----)+(?:.*?)", re.DOTALL),
        ]

        self.decryptRegex = [
            re.compile(r"gpg: CRC error; [\w]{6} - [\w]{6}(?:.*?)"),
            re.compile(r"gpg: cancelled by user"),
            re.compile(r"gpg: invalid armor header: (?:.*?)")
        ]

        self.verifyCheckRegex = [
            re.compile(r"(?:.*?)(?:-----BEGIN PGP MESSAGE-----.*-----END PGP MESSAGE-----)+(?:.*?)", re.DOTALL),
            re.compile(r"(?:.*?)(?:-----BEGIN PGP SIGNED MESSAGE-----.*-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----)+(?:.*?)", re.DOTALL), # --clearsign
        ]

        self.verifyRegex = [
            re.compile(r"gpg: (Signature made .*)", re.DOTALL),
            re.compile(r"gpg: (Good signature from \".*\")", re.DOTALL),
            re.compile(r"gpg: (BAD signature from \".*\")", re.DOTALL),
            re.compile(r"gpg: (no signature found)"),
            re.compile(r"gpg: (the signature could not be verified.)"),
            re.compile(r"gpg: verify signatures failed: Unexpected error")
        ]

    def importCheck(self, bytes):
        if not bytes:
            return False
        text = bytes.decode("UTF-8")
        result = self.importCheckRegex[0].match(text)
        if result:
            return True
        else:
            return False
        
    def importCert(self, data):
        stdout, stderr = subprocess.Popen(
            ["gpg.exe", "--import"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate(data)
        text = filter(None, stderr.decode("UTF-8").replace("\r","").split("\n"))
        rtntext = ""
        icon = False
        for line in text:
            for r in range(len(self.importRegex)):
                result = self.importRegex[r].match(line)
                if result:
                    if r == 0:
                        rtntext += "Key "+result.group(1)+result.group(2)+"\n"
                        icon = self.icons["Info"]
                    elif r == 1:
                        rtntext += "No valid OpenPGP data found\n"
                    elif r == 2:
                        rtntext += "No valid OpenPGP data found\n"
                        icon = self.icons["Crit"]
                    elif r == 3:
                        rtntext += result.group(1)+"\n"
        return rtntext, icon, stderr.decode("UTF-8")

    def listKeys(self):
        pubout, puberr = subprocess.Popen(
            ["gpg.exe", "--list-public-keys", "--with-colons"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate()
        text = filter(None, pubout.decode("UTF-8").replace("\r","").split("\n"))
        keyid = ""
        for line in text:
            for r in range(len(self.listKeysRegex)):
                result = self.listKeysRegex[r].match(line)
                if result:
                    if r == 0:
                        keyid = result.group(1)[8:]
                    if r == 1:
                        if keyid:
                            self.pubkeys[keyid] = result.group(1)
                        keyid = ""
        secout, secerr = subprocess.Popen(
            ["gpg.exe", "--list-secret-keys", "--with-colons"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate()
        text = filter(None, secout.decode("UTF-8").replace("\r","").split("\n"))
        for line in text:
            for r in range(len(self.listKeysRegex)):
                result = self.listKeysRegex[r].match(line)
                if result:
                    if r == 2:
                        keyid = result.group(1)[8:]
                    if r == 3:
                        if keyid:
                            self.seckeys[keyid] = result.group(1)
                        keyid = ""

    def encrypt(self, to_id_list, content):
        popen_list = ["gpg.exe", "--trust-model", "always", "--encrypt"]
        for recipient in to_id_list:
            popen_list.append("--recipient")
            popen_list.append(recipient)
        popen_list.append("--armor")
        stdout, stderr = subprocess.Popen(
            popen_list,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate(content)
        return stdout.decode("UTF-8")

    def sign(self, user, content, algorithm, clearsign):
        popen_list = ["gpg.exe"]
        if clearsign:
            popen_list.append("--clearsign")
            popen_list.append("--digest-algo")
            popen_list.append(algorithm)
        else:
            popen_list.append("--sign")
        popen_list.append("--local-user")
        popen_list.append(user)
        popen_list.append("--armor")
        stdout, stderr = subprocess.Popen(
            popen_list,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate(content)
        text = stderr.decode("UTF-8").replace("\r","").split("\n")
        for line in text:
            if line == "gpg: signing failed: Bad passphrase":
                return 1, "Bad passphrase"
            if line == "gpg: signing failed: Operation cancelled":
                return 1, "Operation cancelled by user"
        return 0, stdout.decode("UTF-8")

    def decryptCheck(self, bytes):
        if not bytes:
            return False
        text = bytes.decode("UTF-8")
        result = self.decryptCheckRegex[0].match(text)
        if result:
            return True
        else:
            return False

    def decrypt(self, data):
        popen_list = ["gpg.exe", "--batch", "--decrypt"]
        stdout, stderr = subprocess.Popen(
            popen_list,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate(data)
        text = filter(None, stderr.decode("UTF-8").replace("\r","").split("\n"))
        icon = self.icons["Info"]
        for line in text:
            for r in range(len(self.decryptRegex)):
                result = self.decryptRegex[r].match(line)
                if result:
                    if r == 0:
                        icon = self.icons["Warn"]
                    if r == 1:
                        icon = self.icons["Warn"]
                    if r == 2:
                    	icon = self.icons["Crit"]
        return stdout.decode("UTF-8"), icon, stderr.decode("UTF-8")

    def verifyCheck(self, bytes):
        if not bytes:
            return False
        result = False
        text = bytes.decode("UTF-8")
        for regex in self.verifyCheckRegex:
           if regex.match(text):
                result = True
        if result:
            return True
        else:
            return False

    def verify(self, data):
        stdout, stderr = subprocess.Popen(
            ["gpg.exe", "--verify"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=self.startupinfo
        ).communicate(data)
        text = filter(None, stderr.decode("UTF-8").replace("\r","").split("\n"))
        rtntitle = ""
        rtntext = ""
        icon = False
        for line in text:
            for r in range(len(self.verifyRegex)):
                result = self.verifyRegex[r].match(line)
                if result:
                    if r == 0:
                        rtntext += result.group(1)+"\n"
                    elif r == 1:
                        rtntitle = result.group(1)
                        icon = self.icons["Info"]
                    elif r == 2:
                        rtntitle = result.group(1)
                        icon = self.icons["Crit"]
                    elif r == 3:
                        rtntitle = "No signature found"
                        icon = self.icons["Crit"]
                    elif r == 4:
                        rtntext += "The signature could not be verified"
                    elif r == 5:
                    	icon = self.icons["Crit"]
                    	rtntext += "Verification failed: Unexpected error"
        return rtntitle, rtntext, icon, stderr.decode("UTF-8")


class PyQtGPGGui(QtGui.QMainWindow):
    def __init__(self):
        super(PyQtGPGGui, self).__init__()
        self.clipboard = Clipboard()
        self.gpghandler = GPGHandler()
            
        self.title = "PyQtGPG"
        self.version = "0.8"
        self.abouttext = """PyQtGPG -- Python Qt4 GPG Wrapper
Copyright © 2013 KevinLi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>."""

        self.iconfilename = "icon.png"
        self.icon = QtGui.QIcon(self.iconfilename)

        self.createActions()
        self.createTray()
        
        self.createEncryptWindow()
        self.createSignWindow()

        self.setWindowIcon(self.icon)
        self.trayIcon.setIcon(self.icon)
        self.trayIcon.setToolTip(self.title)
        self.trayIcon.show()

    def createActions(self):
        self.importAction =  QtGui.QAction("Import",  self, triggered=self.importKey)
        self.encryptAction = QtGui.QAction("Encrypt", self, triggered=self.showEncryptWindow)
        self.signAction =    QtGui.QAction("Sign",    self, triggered=self.showSignWindow)
        self.decryptAction = QtGui.QAction("Decrypt", self, triggered=self.decrypt)
        self.verifyAction =  QtGui.QAction("Verify",  self, triggered=self.verify)
        self.aboutAction =   QtGui.QAction("About",   self, triggered=self.showAboutBox)
        self.quitAction =    QtGui.QAction("Quit",    self, triggered=QtGui.qApp.quit)

    def createTray(self):
        self.trayIconMenu = QtGui.QMenu(self)
        self.trayIconMenu.addAction(self.importAction)
        self.trayIconMenu.addAction(self.encryptAction)
        self.trayIconMenu.addAction(self.signAction)
        self.trayIconMenu.addAction(self.decryptAction)
        self.trayIconMenu.addAction(self.verifyAction)
        self.trayIconMenu.addSeparator()
        self.trayIconMenu.addAction(self.aboutAction)
        self.trayIconMenu.addAction(self.quitAction)

        self.trayIcon = QtGui.QSystemTrayIcon(self)
        self.trayIcon.setContextMenu(self.trayIconMenu)

        self.trayIconMenu.aboutToShow.connect(self.checkMenuItems)
        self.trayIcon.messageClicked.connect(self.messageClicked)

    def createEncryptWindow(self):
        self.encryptWindow = QtGui.QDialog(self, QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowSystemMenuHint)
        self.encryptWindow.setWindowTitle(self.title)
        self.encryptWindow.resize(250, 100)
        self.encryptWindow.groupbox = QtGui.QGroupBox("Encrypt For")

        self.encryptWindow.keysComboBox = []
        self.encryptWindow.keysComboBox.append(QtGui.QComboBox())
        self.encryptWindow.keysComboBox[0].setCurrentIndex(0)

        self.encryptWindow.encryptButton = QtGui.QPushButton("Encrypt")
        self.encryptWindow.encryptButton.setDefault(True)
        self.encryptWindow.encryptButton.clicked.connect(self.encrypt)

        self.encryptWindow.messageLayout = QtGui.QGridLayout()
        self.encryptWindow.messageLayout.addWidget(self.encryptWindow.keysComboBox[0], 0, 0)
        self.encryptWindow.messageLayout.addWidget(self.encryptWindow.encryptButton, 5, 4)
        self.encryptWindow.groupbox.setLayout(self.encryptWindow.messageLayout)
        self.encryptWindow.mainLayout = QtGui.QVBoxLayout()
        self.encryptWindow.mainLayout.addWidget(self.encryptWindow.groupbox,alignment=QtCore.Qt.AlignTop)
        self.encryptWindow.setLayout(self.encryptWindow.mainLayout)

    def createSignWindow(self):
        self.signWindow = QtGui.QDialog(self, QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowSystemMenuHint)
        self.signWindow.setWindowTitle(self.title)
        self.signWindow.resize(250, 100)
        self.signWindow.groupbox = QtGui.QGroupBox("Sign As")

        self.signWindow.keysComboBox = QtGui.QComboBox()
        self.signWindow.keysComboBox.setCurrentIndex(0)

        self.signWindow.signButton = QtGui.QPushButton("Sign Clipboard")
        self.signWindow.signButton.setDefault(True)
        self.signWindow.signButton.clicked.connect(self.sign)

        self.signWindow.messageLayout = QtGui.QGridLayout()
        self.signWindow.messageLayout.addWidget(self.signWindow.keysComboBox, 0, 0)
        self.signWindow.messageLayout.addWidget(self.signWindow.signButton, 5, 4)
        self.signWindow.groupbox.setLayout(self.signWindow.messageLayout)
        self.signWindow.mainLayout = QtGui.QVBoxLayout()
        self.signWindow.mainLayout.addWidget(self.signWindow.groupbox,alignment=QtCore.Qt.AlignTop)
        self.signWindow.setLayout(self.signWindow.mainLayout)

    def showPopup(self, title, body, icon):
        self.trayIcon.showMessage(title, body, icon)

    def setPopupClickMessage(self, title, message):
        self.popupTitle = title
        self.popupMessage = message

    def messageClicked(self):
        QtGui.QMessageBox.information(None, self.popupTitle, self.popupMessage)
        self.setPopupClickMessage("","")
        
    def checkMenuItems(self):
        validClipboard = self.gpghandler.importCheck(self.clipboard.get())
        if not validClipboard:
            self.importAction.setEnabled(False)
        else:
            self.importAction.setEnabled(True)
        if self.clipboard.get() == None:
            self.encryptAction.setEnabled(False)
            self.signAction.setEnabled(False)
        else:
            self.encryptAction.setEnabled(True)
            self.signAction.setEnabled(True)
        validClipboard = self.gpghandler.decryptCheck(self.clipboard.get())
        if not validClipboard:
            self.decryptAction.setEnabled(False)
        else:
            self.decryptAction.setEnabled(True)
        validClipboard = self.gpghandler.verifyCheck(self.clipboard.get())
        if not validClipboard:
            self.verifyAction.setEnabled(False)
        else:
            self.verifyAction.setEnabled(True)

    def importKey(self):
        message, icon, pmessage = self.gpghandler.importCert(self.clipboard.get())
        self.setPopupClickMessage("Import Key", pmessage)
        self.showPopup("Import Key", message, icon)

    def showEncryptWindow(self):

        self.gpghandler.listKeys()
        self.encryptWindow.keysComboBox[0].clear()
        for key in self.gpghandler.pubkeys.keys():
            self.encryptWindow.keysComboBox[0].addItem(
                key + " - " + self.gpghandler.pubkeys[key],
                key
           	)

        self.encryptAction.setEnabled(False)
        self.encryptWindow.showNormal()

    def encrypt(self):
        key = self.encryptWindow.keysComboBox[0].itemData(self.encryptWindow.keysComboBox[0].currentIndex())
        data = self.gpghandler.encrypt([key], self.clipboard.get())
        self.clipboard.set(data)
        self.setPopupClickMessage("Clipboard Encrypted", data)
        self.showPopup(
            "Clipboard Encrypted",
            "Clipboard encrypted for " + key + " - " + self.gpghandler.pubkeys[key],
            self.gpghandler.icons["Info"]
        )
        self.encryptWindow.hide()

    def showSignWindow(self):
        self.gpghandler.listKeys()
        self.signWindow.keysComboBox.clear()
        for key in self.gpghandler.seckeys.keys():
            self.signWindow.keysComboBox.addItem(
                key + " - " + self.gpghandler.seckeys[key],
                key
            )
        self.signWindow.keysComboBox.setCurrentIndex(0)
        self.signWindow.showNormal()

    def sign(self):
        key = self.signWindow.keysComboBox.itemData(self.signWindow.keysComboBox.currentIndex())
        status, data = self.gpghandler.sign(key, self.clipboard.get(), "SHA512", False)
        #PLACEHOLDER DATA IN FUNCTION ABOVE
        if status == 0:
            self.clipboard.set(data)
            self.setPopupClickMessage("Clipboard Signed", data)
            self.showPopup(
                "Clipboard Signed",
                "Clipboard signed as " + key + " - " + self.gpghandler.seckeys[key],
                self.gpghandler.icons["Info"]
            )
        else:
            self.setPopupClickMessage("Clipboard Not Signed", data)
            self.showPopup(
                "Clipboard Not Signed",
                data,
                self.gpghandler.icons["Warn"]
            )
        self.signWindow.hide()

    def decrypt(self):
        data, icon, pmessage = self.gpghandler.decrypt(self.clipboard.get())
        if icon == self.gpghandler.icons["Info"]:
            post = "Succeeded"
            self.clipboard.set(data)
        else:
            post = "Failed"
        self.setPopupClickMessage("Decryption " + post, pmessage)
        self.showPopup(
            "Decryption " + post,
            "",
            icon
        )

    def verify(self):
        title, message, icon, pmessage = self.gpghandler.verify(self.clipboard.get())
        self.setPopupClickMessage("Verification", pmessage)
        self.showPopup(title, message, icon)

    def showAboutBox(self):
        QtGui.QMessageBox.about(self,
            "About {0} {1}".format(self.title, self.version),
            "{0} {1}\n\n{2}".format(self.title, self.version, self.abouttext)
        )

if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    if not QtGui.QSystemTrayIcon.isSystemTrayAvailable():
        sys.exit(1)
    QtGui.QApplication.setQuitOnLastWindowClosed(False)
    main = PyQtGPGGui()
    sys.exit(app.exec_())
