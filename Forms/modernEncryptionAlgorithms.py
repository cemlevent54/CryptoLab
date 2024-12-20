# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'modernEncryptionAlgorithms.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Modern_Encryption_MainWindow(object):
    def setupUi(self, Modern_Encryption_MainWindow):
        Modern_Encryption_MainWindow.setObjectName("Modern_Encryption_MainWindow")
        Modern_Encryption_MainWindow.resize(1246, 865)
        self.centralwidget = QtWidgets.QWidget(Modern_Encryption_MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        
        # Group Box for Algorithm 2
        self.grpBox_Algorithm2 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm2.setGeometry(QtCore.QRect(50, 570, 611, 191))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm2.setFont(font)
        self.grpBox_Algorithm2.setObjectName("grpBox_Algorithm2")
        
        # aes gcm radio button for algorithm 2
        self.rdAESGCM2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdAESGCM2.setGeometry(QtCore.QRect(10, 40, 611, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdAESGCM2.setFont(font)
        self.rdAESGCM2.setObjectName("rdAESGCM2")
        self.rdAESGCM2.setChecked(False)
        
        # rsa pss radio button for algorithm 2
        self.rdRSAPSS2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdRSAPSS2.setGeometry(QtCore.QRect(10, 100, 451, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdRSAPSS2.setFont(font)
        self.rdRSAPSS2.setObjectName("rdRSAPSS2")
        self.rdRSAPSS2.setChecked(False)
        
        # memory usage graph
        self.graphMemoryUsage = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphMemoryUsage.setGeometry(QtCore.QRect(920, 160, 271, 221))
        self.graphMemoryUsage.setObjectName("graphMemoryUsage")
        self.lblMemoryUsage = QtWidgets.QLabel(self.centralwidget)
        self.lblMemoryUsage.setGeometry(QtCore.QRect(970, 120, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblMemoryUsage.setFont(font)
        self.lblMemoryUsage.setObjectName("lblMemoryUsage")
        
        # Group Box for Algorithm Test
        self.grpBox_AlgorithmTest = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_AlgorithmTest.setGeometry(QtCore.QRect(50, 270, 371, 271))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_AlgorithmTest.setFont(font)
        self.grpBox_AlgorithmTest.setObjectName("grpBox_AlgorithmTest")
        
        # text box for encryption
        self.txtBoxEncrypt = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxEncrypt.setGeometry(QtCore.QRect(30, 40, 221, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxEncrypt.setFont(font)
        self.txtBoxEncrypt.setObjectName("txtBoxEncrypt")
        
        # text box for decryption
        self.txtBoxDecrypt = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxDecrypt.setGeometry(QtCore.QRect(30, 200, 221, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxDecrypt.setFont(font)
        self.txtBoxDecrypt.setObjectName("txtBoxDecrypt")
        
        # key text box 1
        self.txtBoxKey1 = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxKey1.setGeometry(QtCore.QRect(270, 40, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxKey1.setFont(font)
        self.txtBoxKey1.setObjectName("txtBoxKey1")
        
        # key text box 2
        self.txtBoxKey2 = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxKey2.setGeometry(QtCore.QRect(270, 200, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxKey2.setFont(font)
        self.txtBoxKey2.setObjectName("txtBoxKey2")
        
        # decrypt button
        self.btnDecrypt = QtWidgets.QPushButton(self.grpBox_AlgorithmTest)
        self.btnDecrypt.setGeometry(QtCore.QRect(220, 130, 93, 28))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnDecrypt.setFont(font)
        self.btnDecrypt.setObjectName("btnDecrypt")
        
        # encrypt button
        self.btnEncrypt = QtWidgets.QPushButton(self.grpBox_AlgorithmTest)
        self.btnEncrypt.setGeometry(QtCore.QRect(90, 130, 93, 28))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnEncrypt.setFont(font)
        self.btnEncrypt.setObjectName("btnEncrypt")
        
        # security label
        self.graphSecurity = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphSecurity.setGeometry(QtCore.QRect(920, 540, 271, 221))
        self.graphSecurity.setObjectName("graphSecurity")
        self.lblSecurity = QtWidgets.QLabel(self.centralwidget)
        self.lblSecurity.setGeometry(QtCore.QRect(980, 500, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblSecurity.setFont(font)
        self.lblSecurity.setObjectName("lblSecurity")
        
        # performance label
        self.lblPerformance = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance.setGeometry(QtCore.QRect(650, 280, 121, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance.setFont(font)
        self.lblPerformance.setObjectName("lblPerformance")
        
        # header label
        self.lblHeader = QtWidgets.QLabel(self.centralwidget)
        self.lblHeader.setGeometry(QtCore.QRect(440, 0, 481, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblHeader.setFont(font)
        self.lblHeader.setObjectName("lblHeader")
        
        # performance graph
        self.graphPerformance = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphPerformance.setGeometry(QtCore.QRect(570, 320, 271, 221))
        self.graphPerformance.setObjectName("graphPerformance")
        
        # compare button
        self.btnCompare = QtWidgets.QPushButton(self.centralwidget)
        self.btnCompare.setGeometry(QtCore.QRect(950, 430, 211, 51))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnCompare.setFont(font)
        self.btnCompare.setObjectName("btnCompare")
        
        # Group Box for Algorithm 1
        self.grpBox_Algorithm1 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm1.setGeometry(QtCore.QRect(50, 70, 611, 181))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm1.setFont(font)
        self.grpBox_Algorithm1.setObjectName("grpBox_Algorithm1")
        
        # aes gcm radio button for algorithm 1
        self.rdAESGCM1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdAESGCM1.setGeometry(QtCore.QRect(10, 30, 581, 31))
        self.rdAESGCM1.setObjectName("rdAESGCM1")
        self.rdAESGCM1.setChecked(False)
        
        # rsa pss radio button for algorithm 1
        self.rdRSAPSS1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdRSAPSS1.setGeometry(QtCore.QRect(10, 90, 421, 20))
        self.rdRSAPSS1.setObjectName("rdRSAPSS1")
        self.rdRSAPSS1.setChecked(False)
        
        
        Modern_Encryption_MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Modern_Encryption_MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1246, 26))
        self.menubar.setObjectName("menubar")
        Modern_Encryption_MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Modern_Encryption_MainWindow)
        self.statusbar.setObjectName("statusbar")
        Modern_Encryption_MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(Modern_Encryption_MainWindow)
        QtCore.QMetaObject.connectSlotsByName(Modern_Encryption_MainWindow)

    def retranslateUi(self, Modern_Encryption_MainWindow):
        _translate = QtCore.QCoreApplication.translate
        Modern_Encryption_MainWindow.setWindowTitle(_translate("Modern_Encryption_MainWindow", "MainWindow"))
        self.grpBox_Algorithm2.setTitle(_translate("Modern_Encryption_MainWindow", "Select Algorithm 2"))
        self.rdAESGCM2.setText(_translate("Modern_Encryption_MainWindow", "AES-GCM(Advanced Encryption Standard - Galois/Counter Mode)"))
        self.rdRSAPSS2.setText(_translate("Modern_Encryption_MainWindow", "RSA-PSS (Probabilistic Signature Scheme)"))
        self.lblMemoryUsage.setText(_translate("Modern_Encryption_MainWindow", "Memory Usage"))
        self.grpBox_AlgorithmTest.setTitle(_translate("Modern_Encryption_MainWindow", "Select Algorithm from left side to test"))
        self.btnDecrypt.setText(_translate("Modern_Encryption_MainWindow", "Decrypt"))
        self.btnEncrypt.setText(_translate("Modern_Encryption_MainWindow", "Encrypt"))
        self.lblSecurity.setText(_translate("Modern_Encryption_MainWindow", "Size of Outputs"))
        self.lblPerformance.setText(_translate("Modern_Encryption_MainWindow", "Performance"))
        self.lblHeader.setText(_translate("Modern_Encryption_MainWindow", "Modern Encryption Algorithms"))
        self.btnCompare.setText(_translate("Modern_Encryption_MainWindow", "Compare Algorithms"))
        self.grpBox_Algorithm1.setTitle(_translate("Modern_Encryption_MainWindow", "Select Algorithm 1 "))
        self.rdAESGCM1.setText(_translate("Modern_Encryption_MainWindow", "AES-GCM(Advanced Encryption Standard - Galois/Counter Mode)"))
        self.rdRSAPSS1.setText(_translate("Modern_Encryption_MainWindow", "RSA-PSS (Probabilistic Signature Scheme)"))


# if __name__ == "__main__":
#     import sys
#     app = QtWidgets.QApplication(sys.argv)
#     Modern_Encryption_MainWindow = QtWidgets.QMainWindow()
#     ui = Ui_Modern_Encryption_MainWindow()
#     ui.setupUi(Modern_Encryption_MainWindow)
#     Modern_Encryption_MainWindow.show()
#     sys.exit(app.exec_())
