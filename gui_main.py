#!/home/first/PycharmProjects/WeaselGUI/venv/bin/python3

import sys
from gui_files.gui import *
from gui_files import certificates_window
from PyQt5 import QtWidgets
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import WeaselAPI.certgen
from OpenSSL import crypto
import twisted
import logging
import WeaselAPI

cur_client_ip = ""
cur_client_port = 0
cur_server_ip = ""
cur_server_port = 0
ca_cer_raw = bytes()
client_cer_raw = bytes()


class ProcessClientServer(QObject):
    received = pyqtSignal()

    def __init__(self):
        QObject.__init__(self)
        self.ready = True

    def do_work(self):
        while True:
            QThread.sleep(1)
            if WeaselAPI.received:
                if self.ready:
                    print("Recieved")
                    global cur_client_ip, cur_client_port, cur_server_ip, cur_server_port
                    cur_client_ip, cur_client_port = WeaselAPI.client_ip, WeaselAPI.client_port
                    cur_server_ip, cur_server_port = WeaselAPI.server_ip, WeaselAPI.server_port
                    self.received.emit()
                    self.ready = False
            else:
                if not WeaselAPI.received:
                    self.ready = True


class ProcessConnectionTerminated(QObject):
    terminated = pyqtSignal()

    def __init__(self):
        QObject.__init__(self)
        self.state = True  # disconnected

    def do_work(self):
        while True:
            QThread.sleep(1)
            if not WeaselAPI.listening and self.state:
                self.terminated.emit()
            self.state = WeaselAPI.listening


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
        self.ui.buttonBox.accepted.connect(lambda: self.parent.send("Certificates loaded successfully!"))

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
    def __init__(self):
        super().__init__()
        self.setFixedSize(650, 380)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.dialog = CertificateSelect(parent=self)

        self.processThread = QThread()
        self.worker = ProcessClientServer()
        self.worker.moveToThread(self.processThread)
        self.worker.received.connect(lambda: self.send("Client captured! See additional network data below"))
        self.worker.received.connect(self.setClientServerData)
        self.processThread.started.connect(self.worker.do_work)
        self.processThread.start()

        self.connectionThread = QThread()
        self.connectionWorker = ProcessConnectionTerminated()
        self.connectionWorker.moveToThread(self.connectionThread)
        self.connectionWorker.terminated.connect(lambda: self.setStartActive())
        self.connectionWorker.terminated.connect(lambda: self.setCertActive())
        self.connectionWorker.terminated.connect(lambda: self.send("Connection is not active."))
        self.connectionThread.started.connect(self.connectionWorker.do_work)
        self.connectionThread.start()

        loggingBrowser = QPlainTextEditLoggerHandler(self.ui.LoggingBrowser)
        logging.getLogger().addHandler(loggingBrowser)
        logging.getLogger().setLevel(logging.DEBUG)

        self.setupSignals()

    def send(self, message):
        self.ui.MessageBrowser.appendPlainText(message)

    def setCertActive(self):
        self.ui.loadCertificates.setEnabled(True)

    def setStartActive(self):
        self.ui.startProxy.setEnabled(True)

    def setupSignals(self):
        self.ui.loadCertificates.clicked.connect(self.selectCertificates)
        self.ui.startProxy.clicked.connect(self.startListening)

    def selectCertificates(self):
        print("Selecting certs")
        self.dialog.exec()

    def startListening(self):
        import WeaselAPI.WeaselTCP
        self.ui.startProxy.setEnabled(False)
        self.ui.loadCertificates.setEnabled(False)

        self.ui.LoggingBrowser.clear()
        self.ui.MessageBrowser.clear()
        self.ui.ClientInfo.clear()
        self.ui.ServerInfo.clear()

        weaselProxy = WeaselAPI.WeaselTCP.WeaselProxy(bind_port=8080, interface="192.168.10.128")
        weaselProxy.start(WeaselAPI.certgen.CertificateChain(client_cer_raw, ca_cer_raw))
        print(f"LISTENING: {WeaselAPI.listening}")
        self.send("Proxy has been launched. Listening...")

    def setClientServerData(self):
        self.ui.ClientInfo.setText(cur_client_ip + ":" + str(cur_client_port))
        self.ui.ServerInfo.setText(cur_server_ip + ":" + str(cur_server_port))

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
