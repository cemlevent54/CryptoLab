# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'SymmetricEncryptionAlgorithms.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_SymmetricEncryption_MainWindow(object):
    def setupUi(self, SymmetricEncryption_MainWindow):
        SymmetricEncryption_MainWindow.setObjectName("SymmetricEncryption_MainWindow")
        SymmetricEncryption_MainWindow.resize(1243, 848)
        self.centralwidget = QtWidgets.QWidget(SymmetricEncryption_MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.grpBox_Algorithm1 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm1.setGeometry(QtCore.QRect(10, 50, 351, 321))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm1.setFont(font)
        self.grpBox_Algorithm1.setObjectName("grpBox_Algorithm1")
        self.rdAES1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdAES1.setGeometry(QtCore.QRect(10, 30, 341, 31))
        self.rdAES1.setObjectName("rdAES1")
        self.rdTwofish1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdTwofish1.setGeometry(QtCore.QRect(10, 270, 211, 20))
        self.rdTwofish1.setObjectName("rdTwofish1")
        self.rdDES1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdDES1.setGeometry(QtCore.QRect(10, 70, 301, 20))
        self.rdDES1.setObjectName("rdDES1")
        self.rdRivest1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdRivest1.setGeometry(QtCore.QRect(10, 190, 211, 20))
        self.rdRivest1.setObjectName("rdRivest1")
        self.rdBlowfish1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdBlowfish1.setGeometry(QtCore.QRect(10, 150, 211, 20))
        self.rdBlowfish1.setObjectName("rdBlowfish1")
        self.rdChaCha1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdChaCha1.setGeometry(QtCore.QRect(10, 230, 211, 20))
        self.rdChaCha1.setObjectName("rdChaCha1")
        self.rd3DES1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rd3DES1.setGeometry(QtCore.QRect(10, 110, 211, 20))
        self.rd3DES1.setObjectName("rd3DES1")
        self.grpBox_Algorithm2 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm2.setGeometry(QtCore.QRect(10, 420, 351, 351))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm2.setFont(font)
        self.grpBox_Algorithm2.setObjectName("grpBox_Algorithm2")
        self.rdAES2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdAES2.setGeometry(QtCore.QRect(10, 40, 331, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdAES2.setFont(font)
        self.rdAES2.setObjectName("rdAES2")
        self.rdTwofish2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdTwofish2.setGeometry(QtCore.QRect(10, 280, 211, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdTwofish2.setFont(font)
        self.rdTwofish2.setObjectName("rdTwofish2")
        self.rdChaCha2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdChaCha2.setGeometry(QtCore.QRect(10, 240, 211, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdChaCha2.setFont(font)
        self.rdChaCha2.setObjectName("rdChaCha2")
        self.rdRivest2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdRivest2.setGeometry(QtCore.QRect(10, 200, 211, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdRivest2.setFont(font)
        self.rdRivest2.setObjectName("rdRivest2")
        self.rd3DES2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rd3DES2.setGeometry(QtCore.QRect(10, 120, 211, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rd3DES2.setFont(font)
        self.rd3DES2.setObjectName("rd3DES2")
        self.rdBlowfish2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdBlowfish2.setGeometry(QtCore.QRect(10, 160, 211, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdBlowfish2.setFont(font)
        self.rdBlowfish2.setObjectName("rdBlowfish2")
        self.rdDES2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdDES2.setGeometry(QtCore.QRect(10, 80, 331, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdDES2.setFont(font)
        self.rdDES2.setObjectName("rdDES2")
        self.grpBox_AlgorithmTest = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_AlgorithmTest.setGeometry(QtCore.QRect(420, 90, 381, 271))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_AlgorithmTest.setFont(font)
        self.grpBox_AlgorithmTest.setObjectName("grpBox_AlgorithmTest")
        self.txtBoxEncrypt = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxEncrypt.setGeometry(QtCore.QRect(30, 40, 221, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxEncrypt.setFont(font)
        self.txtBoxEncrypt.setObjectName("txtBoxEncrypt")
        self.txtBoxDecrypt = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxDecrypt.setGeometry(QtCore.QRect(30, 200, 221, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxDecrypt.setFont(font)
        self.txtBoxDecrypt.setObjectName("txtBoxDecrypt")
        self.txtBoxKey1 = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxKey1.setGeometry(QtCore.QRect(270, 40, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxKey1.setFont(font)
        self.txtBoxKey1.setObjectName("txtBoxKey1")
        self.txtBoxKey2 = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxKey2.setGeometry(QtCore.QRect(270, 200, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxKey2.setFont(font)
        self.txtBoxKey2.setObjectName("txtBoxKey2")
        self.btnDecrypt = QtWidgets.QPushButton(self.grpBox_AlgorithmTest)
        self.btnDecrypt.setGeometry(QtCore.QRect(220, 130, 93, 28))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnDecrypt.setFont(font)
        self.btnDecrypt.setObjectName("btnDecrypt")
        self.btnEncrypt = QtWidgets.QPushButton(self.grpBox_AlgorithmTest)
        self.btnEncrypt.setGeometry(QtCore.QRect(90, 130, 93, 28))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnEncrypt.setFont(font)
        self.btnEncrypt.setObjectName("btnEncrypt")
        self.graphPerformance = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphPerformance.setGeometry(QtCore.QRect(870, 240, 271, 221))
        self.graphPerformance.setObjectName("graphPerformance")
        self.graphSecurity = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphSecurity.setGeometry(QtCore.QRect(870, 540, 271, 221))
        self.graphSecurity.setObjectName("graphSecurity")
        self.graphMemoryUsage = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphMemoryUsage.setGeometry(QtCore.QRect(510, 540, 271, 221))
        self.graphMemoryUsage.setObjectName("graphMemoryUsage")
        self.lblPerformance = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance.setGeometry(QtCore.QRect(950, 200, 121, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance.setFont(font)
        self.lblPerformance.setObjectName("lblPerformance")
        self.lblSecurity = QtWidgets.QLabel(self.centralwidget)
        self.lblSecurity.setGeometry(QtCore.QRect(930, 500, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblSecurity.setFont(font)
        self.lblSecurity.setObjectName("lblSecurity")
        self.lblMemoryUsage = QtWidgets.QLabel(self.centralwidget)
        self.lblMemoryUsage.setGeometry(QtCore.QRect(560, 500, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblMemoryUsage.setFont(font)
        self.lblMemoryUsage.setObjectName("lblMemoryUsage")
        self.lblPerformance_2 = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance_2.setGeometry(QtCore.QRect(420, 10, 481, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance_2.setFont(font)
        self.lblPerformance_2.setObjectName("lblPerformance_2")
        self.btnCompare = QtWidgets.QPushButton(self.centralwidget)
        self.btnCompare.setGeometry(QtCore.QRect(530, 410, 211, 51))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnCompare.setFont(font)
        self.btnCompare.setObjectName("btnCompare")
        SymmetricEncryption_MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(SymmetricEncryption_MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1243, 26))
        self.menubar.setObjectName("menubar")
        SymmetricEncryption_MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SymmetricEncryption_MainWindow)
        self.statusbar.setObjectName("statusbar")
        SymmetricEncryption_MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(SymmetricEncryption_MainWindow)
        QtCore.QMetaObject.connectSlotsByName(SymmetricEncryption_MainWindow)

    def retranslateUi(self, SymmetricEncryption_MainWindow):
        _translate = QtCore.QCoreApplication.translate
        SymmetricEncryption_MainWindow.setWindowTitle(_translate("SymmetricEncryption_MainWindow", "MainWindow"))
        self.grpBox_Algorithm1.setTitle(_translate("SymmetricEncryption_MainWindow", "Select Algorithm 1 "))
        self.rdAES1.setText(_translate("SymmetricEncryption_MainWindow", "AES(Advanced Encryption Standard)"))
        self.rdTwofish1.setText(_translate("SymmetricEncryption_MainWindow", "Twofish"))
        self.rdDES1.setText(_translate("SymmetricEncryption_MainWindow", "DES(Data Encryption Standard)"))
        self.rdRivest1.setText(_translate("SymmetricEncryption_MainWindow", "RC4(Rivest Cipher 4)"))
        self.rdBlowfish1.setText(_translate("SymmetricEncryption_MainWindow", "Blowfish"))
        self.rdChaCha1.setText(_translate("SymmetricEncryption_MainWindow", "ChaCha20"))
        self.rd3DES1.setText(_translate("SymmetricEncryption_MainWindow", "3DES(Triple DES)"))
        self.grpBox_Algorithm2.setTitle(_translate("SymmetricEncryption_MainWindow", "Select Algorithm 2"))
        self.rdAES2.setText(_translate("SymmetricEncryption_MainWindow", "AES(Advanced Encryption Standard)"))
        self.rdTwofish2.setText(_translate("SymmetricEncryption_MainWindow", "Twofish"))
        self.rdChaCha2.setText(_translate("SymmetricEncryption_MainWindow", "ChaCha20"))
        self.rdRivest2.setText(_translate("SymmetricEncryption_MainWindow", "RC4(Rivest Cipher 4)"))
        self.rd3DES2.setText(_translate("SymmetricEncryption_MainWindow", "3DES(Triple DES)"))
        self.rdBlowfish2.setText(_translate("SymmetricEncryption_MainWindow", "Blowfish"))
        self.rdDES2.setText(_translate("SymmetricEncryption_MainWindow", "DES(Data Encryption Standard)"))
        self.grpBox_AlgorithmTest.setTitle(_translate("SymmetricEncryption_MainWindow", "Select Algorithm from left side to test"))
        self.btnDecrypt.setText(_translate("SymmetricEncryption_MainWindow", "Decrypt"))
        self.btnEncrypt.setText(_translate("SymmetricEncryption_MainWindow", "Encrypt"))
        self.lblPerformance.setText(_translate("SymmetricEncryption_MainWindow", "Performance"))
        self.lblSecurity.setText(_translate("SymmetricEncryption_MainWindow", "Frequency Analysis"))
        self.lblMemoryUsage.setText(_translate("SymmetricEncryption_MainWindow", "Memory Usage"))
        self.lblPerformance_2.setText(_translate("SymmetricEncryption_MainWindow", "Symmetric Encryption Algorithms"))
        self.btnCompare.setText(_translate("SymmetricEncryption_MainWindow", "Compare Algorithms"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    SymmetricEncryption_MainWindow = QtWidgets.QMainWindow()
    ui = Ui_SymmetricEncryption_MainWindow()
    ui.setupUi(SymmetricEncryption_MainWindow)
    SymmetricEncryption_MainWindow.show()
    sys.exit(app.exec_())
