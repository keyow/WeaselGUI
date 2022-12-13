#!/home/first/PycharmProjects/WeaselGUI/venv/bin/python3

import sys
from gui_files.gui import *
from gui_files import certificates_window
from PyQt5 import QtCore, QtGui, QtWidgets
import WeaselAPI.certgen
from OpenSSL import crypto
from threading import *
import twisted
import logging

ca_cer_raw = bytes()
client_cer_raw = bytes()


class CertificateSelect(QtWidgets.QDialog):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        print(self.parent)
        self.ui = certificates_window.Ui_Dialog()
        self.ui.setupUi(self)
        self.setupSignals()

    def setupSignals(self):
        self.ui.buttonBox.accepted.connect(self.saveCertificateEvent)

    def saveCertificateEvent(self):
        CA_KEY, CA_CERT = WeaselAPI.certgen.generateCA(
            self.ui.CA_country.toPlainText(),
            self.ui.CA_State.toPlainText(),
            self.ui.CA_Locality.toPlainText(),
            self.ui.CA_Organization.toPlainText(),
            self.ui.CA_OrganizationUnit.toPlainText(),
            self.ui.CA_CommonName.toPlainText(),
            self.ui.CA_Email.toPlainText(),
            self.ui.CA_NotBefore.toPlainText(),
            self.ui.CA_NotAfter.toPlainText())

        REQ = WeaselAPI.certgen.generateRequest(
            self.ui.Client_Country.toPlainText(),
            self.ui.Client_State.toPlainText(),
            self.ui.Client_Locality.toPlainText(),
            self.ui.Client_Organization.toPlainText(),
            self.ui.Client_OrganizationUnit.toPlainText(),
            self.ui.Client_CommonName.toPlainText(),
            self.ui.Client_Email.toPlainText())

        CLIENT_CERT = WeaselAPI.certgen.generateCertificate(
            self.ui.Client_NotBefore.toPlainText(), self.ui.Client_NotAfter.toPlainText(),
            request=REQ, issuer=CA_CERT, issuer_key=CA_KEY)

        ca_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CA_CERT)
        with open("misc/certinfo/genCA_cert.pem", 'wb') as f:
            f.write(ca_cer_pem)

        client_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CLIENT_CERT)
        with open("misc/certinfo/genClient_cert.pem", 'wb') as f:
            f.write(client_cer_pem)

        global ca_cer_raw, client_cer_raw
        ca_cer_raw = crypto.dump_certificate(crypto.FILETYPE_ASN1, CA_CERT)
        client_cer_raw = crypto.dump_certificate(crypto.FILETYPE_ASN1, CLIENT_CERT)

        self.parent.ui.startProxy.setEnabled(True)


class QPlainTextEditLoggerHandler(logging.Handler):
    def __init__(self, signedPlainTextWidget):
        super().__init__()
        self.widget = signedPlainTextWidget
        self.widget.setReadOnly(True)

    def emit(self, record):
        msg = self.format(record)
        self.widget.appendPlainText(msg)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__()
        self.setFixedSize(650, 370)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.dialog = CertificateSelect(parent=self)

        loggingBrowser = QPlainTextEditLoggerHandler(self.ui.LoggingBrowser)
        logging.getLogger().addHandler(loggingBrowser)
        logging.getLogger().setLevel(logging.DEBUG)

        self.setupSignals()

    def setupSignals(self):
        self.ui.loadCertificates.clicked.connect(self.selectCertificates)
        self.ui.startProxy.clicked.connect(self.startListening)

    def selectCertificates(self):
        print("Selecting certs")
        self.dialog.exec()

    @staticmethod
    def startListening(self):
        import WeaselAPI.WeaselTCP
        weaselProxy = WeaselAPI.WeaselTCP.WeaselProxy(bind_port=8080, interface="192.168.10.128")
        weaselProxy.start(WeaselAPI.certgen.CertificateChain(client_cer_raw, ca_cer_raw))

    def closeEvent(self, event):
        super(MainWindow, self).closeEvent(event)
        from subprocess import call
        call(['sudo', 'bash', './scripts/reset.sh'])
        twisted.internet.reactor.stop()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()

    import qt5reactor
    qt5reactor.install()

    from twisted.internet import reactor
    sys.exit(reactor.run())
