# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(650, 370)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setStyleSheet("background: gray;")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 0, 250, 40))
        self.label.setObjectName("label")
        self.gridLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(340, 290, 301, 51))
        self.gridLayoutWidget.setObjectName("gridLayoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setHorizontalSpacing(6)
        self.gridLayout.setObjectName("gridLayout")
        self.ServerLabel = QtWidgets.QLabel(self.gridLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.ServerLabel.sizePolicy().hasHeightForWidth())
        self.ServerLabel.setSizePolicy(sizePolicy)
        self.ServerLabel.setObjectName("ServerLabel")
        self.gridLayout.addWidget(self.ServerLabel, 1, 0, 1, 1)
        self.ClientLabel = QtWidgets.QLabel(self.gridLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.ClientLabel.sizePolicy().hasHeightForWidth())
        self.ClientLabel.setSizePolicy(sizePolicy)
        self.ClientLabel.setObjectName("ClientLabel")
        self.gridLayout.addWidget(self.ClientLabel, 0, 0, 1, 1)
        self.ClientInfo = QtWidgets.QLabel(self.gridLayoutWidget)
        self.ClientInfo.setText("")
        self.ClientInfo.setObjectName("ClientInfo")
        self.gridLayout.addWidget(self.ClientInfo, 0, 1, 1, 1)
        self.ServerInfo = QtWidgets.QLabel(self.gridLayoutWidget)
        self.ServerInfo.setText("")
        self.ServerInfo.setObjectName("ServerInfo")
        self.gridLayout.addWidget(self.ServerInfo, 1, 1, 1, 1)
        self.startProxy = QtWidgets.QPushButton(self.centralwidget)
        self.startProxy.setEnabled(False)
        self.startProxy.setGeometry(QtCore.QRect(340, 240, 301, 41))
        self.startProxy.setObjectName("startProxy")
        self.loadCertificates = QtWidgets.QPushButton(self.centralwidget)
        self.loadCertificates.setGeometry(QtCore.QRect(340, 40, 301, 41))
        self.loadCertificates.setObjectName("loadCertificates")
        self.LoggingBrowser = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.LoggingBrowser.setGeometry(QtCore.QRect(10, 40, 321, 301))
        self.LoggingBrowser.setObjectName("LoggingBrowser")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 650, 22))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "WeaselProxy"))
        self.label.setText(_translate("MainWindow", "Logs"))
        self.ServerLabel.setText(_translate("MainWindow", "Server"))
        self.ClientLabel.setText(_translate("MainWindow", "Client"))
        self.startProxy.setText(_translate("MainWindow", "Start"))
        self.loadCertificates.setText(_translate("MainWindow", "Load certificates"))