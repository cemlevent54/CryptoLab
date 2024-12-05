# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'AsymmetricEncryptionAlgorithms.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Asymmetic_Encryption_MainWindow(object):
    def setupUi(self, Asymmetic_Encryption_MainWindow):
        Asymmetic_Encryption_MainWindow.setObjectName("Asymmetic_Encryption_MainWindow")
        Asymmetic_Encryption_MainWindow.resize(1232, 860)
        self.centralwidget = QtWidgets.QWidget(Asymmetic_Encryption_MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.lblHeader = QtWidgets.QLabel(self.centralwidget)
        self.lblHeader.setGeometry(QtCore.QRect(430, 30, 491, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblHeader.setFont(font)
        self.lblHeader.setObjectName("lblHeader")
        self.grpBox_Algorithm1 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm1.setGeometry(QtCore.QRect(20, 70, 371, 181))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm1.setFont(font)
        self.grpBox_Algorithm1.setObjectName("grpBox_Algorithm1")
        self.rdRSA1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdRSA1.setGeometry(QtCore.QRect(10, 30, 341, 31))
        self.rdRSA1.setObjectName("rdRSA1")
        self.rdDSA1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdDSA1.setGeometry(QtCore.QRect(10, 70, 311, 20))
        self.rdDSA1.setObjectName("rdDSA1")
        self.rd3DES1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rd3DES1.setGeometry(QtCore.QRect(10, 110, 301, 20))
        self.rd3DES1.setObjectName("rd3DES1")
        self.lblMemoryUsage = QtWidgets.QLabel(self.centralwidget)
        self.lblMemoryUsage.setGeometry(QtCore.QRect(950, 120, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblMemoryUsage.setFont(font)
        self.lblMemoryUsage.setObjectName("lblMemoryUsage")
        self.grpBox_Algorithm2 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm2.setGeometry(QtCore.QRect(20, 570, 371, 191))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm2.setFont(font)
        self.grpBox_Algorithm2.setObjectName("grpBox_Algorithm2")
        self.rdRSA2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdRSA2.setGeometry(QtCore.QRect(10, 40, 331, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdRSA2.setFont(font)
        self.rdRSA2.setObjectName("rdRSA2")
        self.rd3DES2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rd3DES2.setGeometry(QtCore.QRect(10, 120, 311, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rd3DES2.setFont(font)
        self.rd3DES2.setObjectName("rd3DES2")
        self.rdDSA2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdDSA2.setGeometry(QtCore.QRect(10, 80, 331, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdDSA2.setFont(font)
        self.rdDSA2.setObjectName("rdDSA2")
        self.graphMemoryUsage = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphMemoryUsage.setGeometry(QtCore.QRect(900, 160, 271, 221))
        self.graphMemoryUsage.setObjectName("graphMemoryUsage")
        self.graphSecurity = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphSecurity.setGeometry(QtCore.QRect(710, 550, 271, 221))
        self.graphSecurity.setObjectName("graphSecurity")
        self.lblSecurity = QtWidgets.QLabel(self.centralwidget)
        self.lblSecurity.setGeometry(QtCore.QRect(770, 510, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblSecurity.setFont(font)
        self.lblSecurity.setObjectName("lblSecurity")
        self.lblPerformance = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance.setGeometry(QtCore.QRect(580, 120, 121, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance.setFont(font)
        self.lblPerformance.setObjectName("lblPerformance")
        self.grpBox_AlgorithmTest = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_AlgorithmTest.setGeometry(QtCore.QRect(20, 270, 371, 271))
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
        self.graphPerformance.setGeometry(QtCore.QRect(500, 160, 271, 221))
        self.graphPerformance.setObjectName("graphPerformance")
        self.btnCompare = QtWidgets.QPushButton(self.centralwidget)
        self.btnCompare.setGeometry(QtCore.QRect(730, 430, 211, 51))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnCompare.setFont(font)
        self.btnCompare.setObjectName("btnCompare")
        Asymmetic_Encryption_MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Asymmetic_Encryption_MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1232, 26))
        self.menubar.setObjectName("menubar")
        Asymmetic_Encryption_MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Asymmetic_Encryption_MainWindow)
        self.statusbar.setObjectName("statusbar")
        Asymmetic_Encryption_MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(Asymmetic_Encryption_MainWindow)
        QtCore.QMetaObject.connectSlotsByName(Asymmetic_Encryption_MainWindow)

    def retranslateUi(self, Asymmetic_Encryption_MainWindow):
        _translate = QtCore.QCoreApplication.translate
        Asymmetic_Encryption_MainWindow.setWindowTitle(_translate("Asymmetic_Encryption_MainWindow", "MainWindow"))
        self.lblHeader.setText(_translate("Asymmetic_Encryption_MainWindow", "Asymmetric Encryption Algorithms"))
        self.grpBox_Algorithm1.setTitle(_translate("Asymmetic_Encryption_MainWindow", "Select Algorithm 1 "))
        self.rdRSA1.setText(_translate("Asymmetic_Encryption_MainWindow", "RSA (Rivest–Shamir–Adleman)"))
        self.rdDSA1.setText(_translate("Asymmetic_Encryption_MainWindow", "DSA(Digital Signature Algorithm)"))
        self.rd3DES1.setText(_translate("Asymmetic_Encryption_MainWindow", "Diffie-Hellman Key Exchange"))
        self.lblMemoryUsage.setText(_translate("Asymmetic_Encryption_MainWindow", "Memory Usage"))
        self.grpBox_Algorithm2.setTitle(_translate("Asymmetic_Encryption_MainWindow", "Select Algorithm 2"))
        self.rdRSA2.setText(_translate("Asymmetic_Encryption_MainWindow", "RSA (Rivest–Shamir–Adleman)"))
        self.rd3DES2.setText(_translate("Asymmetic_Encryption_MainWindow", "Diffie-Hellman Key Exchange"))
        self.rdDSA2.setText(_translate("Asymmetic_Encryption_MainWindow", "DSA(Digital Signature Algorithm)"))
        self.lblSecurity.setText(_translate("Asymmetic_Encryption_MainWindow", "Frequency Analysis"))
        self.lblPerformance.setText(_translate("Asymmetic_Encryption_MainWindow", "Performance"))
        self.grpBox_AlgorithmTest.setTitle(_translate("Asymmetic_Encryption_MainWindow", "Select Algorithm from left side to test"))
        self.btnDecrypt.setText(_translate("Asymmetic_Encryption_MainWindow", "Decrypt"))
        self.btnEncrypt.setText(_translate("Asymmetic_Encryption_MainWindow", "Encrypt"))
        self.btnCompare.setText(_translate("Asymmetic_Encryption_MainWindow", "Compare Algorithms"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Asymmetic_Encryption_MainWindow = QtWidgets.QMainWindow()
    ui = Ui_Asymmetic_Encryption_MainWindow()
    ui.setupUi(Asymmetic_Encryption_MainWindow)
    Asymmetic_Encryption_MainWindow.show()
    sys.exit(app.exec_())