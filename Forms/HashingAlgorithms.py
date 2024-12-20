# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'HashingAlgorithms.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Hashing_Algorithms_MainWindow(object):
    def setupUi(self, Hashing_Algorithms_MainWindow):
        Hashing_Algorithms_MainWindow.setObjectName("Hashing_Algorithms_MainWindow")
        Hashing_Algorithms_MainWindow.resize(1449, 863)
        self.centralwidget = QtWidgets.QWidget(Hashing_Algorithms_MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        
        # group box for algorithm 1
        self.grpBox_Algorithm1 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm1.setGeometry(QtCore.QRect(60, 30, 271, 181))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm1.setFont(font)
        self.grpBox_Algorithm1.setObjectName("grpBox_Algorithm1")
        
        # md5 radio button for algorithm 1
        self.rdMD5_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdMD5_1.setGeometry(QtCore.QRect(10, 30, 161, 31))
        self.rdMD5_1.setObjectName("rdMD5_1")
        self.rdMD5_1.setChecked(False)
        
        # sha1 radio button for algorithm 1
        self.rdSHA1_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdSHA1_1.setGeometry(QtCore.QRect(10, 70, 131, 20))
        self.rdSHA1_1.setObjectName("rdSHA1_1")
        self.rdSHA1_1.setChecked(False)
        
        # sha256 radio button for algorithm 1
        self.rdSHA256_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdSHA256_1.setGeometry(QtCore.QRect(10, 100, 131, 20))
        self.rdSHA256_1.setObjectName("rdSHA256_1")
        self.rdSHA256_1.setChecked(False)
        
        # sha512 radio button for algorithm 1
        self.rdSHA512_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdSHA512_1.setGeometry(QtCore.QRect(10, 140, 131, 20))
        self.rdSHA512_1.setObjectName("rdSHA512_1")
        self.rdSHA512_1.setChecked(False)
        
        # blake2b radio button for algorithm 1
        self.rdBlake2b_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdBlake2b_1.setGeometry(QtCore.QRect(130, 40, 131, 20))
        self.rdBlake2b_1.setObjectName("rdBlake2b_1")
        
        # blake2s radio button for algorithm 1
        self.rdBlake2s_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdBlake2s_1.setGeometry(QtCore.QRect(130, 70, 131, 20))
        self.rdBlake2s_1.setObjectName("rdBlake2s_1")
        self.rdBlake2s_1.setChecked(False)
        
        # argon2 radio button for algorithm 1
        self.rdArgon2_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdArgon2_1.setGeometry(QtCore.QRect(130, 100, 131, 20))
        self.rdArgon2_1.setObjectName("rdArgon2_1")
        self.rdArgon2_1.setChecked(False)
        
        # crc32 radio button for algorithm 1
        self.rdCRC32_1 = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdCRC32_1.setGeometry(QtCore.QRect(130, 140, 131, 20))
        self.rdCRC32_1.setObjectName("rdCRC32_1")
        self.rdCRC32_1.setChecked(False)
        
        # group box for algorithm test
        self.grpBox_AlgorithmTest = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_AlgorithmTest.setGeometry(QtCore.QRect(40, 270, 371, 271))
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
        
        # text box for decryption, which is displayed as 'irreversible'
        self.txtBoxDecrypt = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxDecrypt.setGeometry(QtCore.QRect(30, 200, 221, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxDecrypt.setFont(font)
        self.txtBoxDecrypt.setObjectName("txtBoxDecrypt")
        
        # key 1 text box for encryption
        self.txtBoxKey1 = QtWidgets.QTextEdit(self.grpBox_AlgorithmTest)
        self.txtBoxKey1.setGeometry(QtCore.QRect(270, 40, 91, 41))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.txtBoxKey1.setFont(font)
        self.txtBoxKey1.setObjectName("txtBoxKey1")
        
        # key 2 text box for decryption
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
        
        # compare button
        self.btnCompare = QtWidgets.QPushButton(self.centralwidget)
        self.btnCompare.setGeometry(QtCore.QRect(800, 430, 211, 51))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnCompare.setFont(font)
        self.btnCompare.setObjectName("btnCompare")
        
        # memory usage label
        self.lblMemoryUsage = QtWidgets.QLabel(self.centralwidget)
        self.lblMemoryUsage.setGeometry(QtCore.QRect(1020, 120, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblMemoryUsage.setFont(font)
        self.lblMemoryUsage.setObjectName("lblMemoryUsage")
        
        # performance label
        self.lblPerformance_2 = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance_2.setGeometry(QtCore.QRect(590, 30, 291, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance_2.setFont(font)
        self.lblPerformance_2.setObjectName("lblPerformance_2")
        
        # memory usage graph
        self.graphMemoryUsage = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphMemoryUsage.setGeometry(QtCore.QRect(970, 160, 271, 221))
        self.graphMemoryUsage.setObjectName("graphMemoryUsage")
        
        # security label
        self.lblSecurity = QtWidgets.QLabel(self.centralwidget)
        self.lblSecurity.setGeometry(QtCore.QRect(840, 510, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblSecurity.setFont(font)
        self.lblSecurity.setObjectName("lblSecurity")
        
        # performance graph
        self.graphPerformance = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphPerformance.setGeometry(QtCore.QRect(570, 160, 271, 221))
        self.graphPerformance.setObjectName("graphPerformance")
        
        # security graph
        self.graphSecurity = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphSecurity.setGeometry(QtCore.QRect(780, 550, 271, 221))
        self.graphSecurity.setObjectName("graphSecurity")
        
        # performance label
        self.lblPerformance = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance.setGeometry(QtCore.QRect(650, 120, 121, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance.setFont(font)
        self.lblPerformance.setObjectName("lblPerformance")
        
        # group box for algorithm 2
        self.grpBox_Algorithm2 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm2.setGeometry(QtCore.QRect(60, 580, 271, 181))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm2.setFont(font)
        self.grpBox_Algorithm2.setObjectName("grpBox_Algorithm2")
        
        # md5 radio button for algorithm 2
        self.rdMD5_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdMD5_2.setGeometry(QtCore.QRect(10, 30, 161, 31))
        self.rdMD5_2.setObjectName("rdMD5_2")
        self.rdMD5_2.setChecked(False)
        
        # sha1 radio button for algorithm 2
        self.rdSHA1_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdSHA1_2.setGeometry(QtCore.QRect(10, 70, 131, 20))
        self.rdSHA1_2.setObjectName("rdSHA1_2")
        self.rdSHA1_2.setChecked(False)
        
        # sha256 radio button for algorithm 2
        self.rdSHA256_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdSHA256_2.setGeometry(QtCore.QRect(10, 100, 131, 20))
        self.rdSHA256_2.setObjectName("rdSHA256_2")
        self.rdSHA256_2.setChecked(False)
        
        # sha512 radio button for algorithm 2
        self.rdSHA512_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdSHA512_2.setGeometry(QtCore.QRect(10, 140, 131, 20))
        self.rdSHA512_2.setObjectName("rdSHA512_2")
        self.rdSHA512_2.setChecked(False)
        
        # blake2b radio button for algorithm 2
        self.rdBlake2b_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdBlake2b_2.setGeometry(QtCore.QRect(130, 40, 131, 20))
        self.rdBlake2b_2.setObjectName("rdBlake2b_2")
        self.rdBlake2b_2.setChecked(False)
        
        # blake2s radio button for algorithm 2
        self.rdBlake2s_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdBlake2s_2.setGeometry(QtCore.QRect(130, 70, 131, 20))
        self.rdBlake2s_2.setObjectName("rdBlake2s_2")
        self.rdBlake2s_2.setChecked(False)
        
        # argon2 radio button for algorithm 2
        self.rdArgon2_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdArgon2_2.setGeometry(QtCore.QRect(130, 100, 131, 20))
        self.rdArgon2_2.setObjectName("rdArgon2_2")
        self.rdArgon2_2.setChecked(False)
        
        # crc32 radio button for algorithm 2
        self.rdCRC32_2 = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdCRC32_2.setGeometry(QtCore.QRect(130, 140, 131, 20))
        self.rdCRC32_2.setObjectName("rdCRC32_2")
        self.rdCRC32_2.setChecked(False)
        
        Hashing_Algorithms_MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Hashing_Algorithms_MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1449, 26))
        self.menubar.setObjectName("menubar")
        Hashing_Algorithms_MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Hashing_Algorithms_MainWindow)
        self.statusbar.setObjectName("statusbar")
        Hashing_Algorithms_MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(Hashing_Algorithms_MainWindow)
        QtCore.QMetaObject.connectSlotsByName(Hashing_Algorithms_MainWindow)

    def retranslateUi(self, Hashing_Algorithms_MainWindow):
        _translate = QtCore.QCoreApplication.translate
        Hashing_Algorithms_MainWindow.setWindowTitle(_translate("Hashing_Algorithms_MainWindow", "MainWindow"))
        self.grpBox_Algorithm1.setTitle(_translate("Hashing_Algorithms_MainWindow", "Select Algorithm 1 "))
        self.rdMD5_1.setText(_translate("Hashing_Algorithms_MainWindow", "MD5"))
        self.rdSHA1_1.setText(_translate("Hashing_Algorithms_MainWindow", "SHA 1"))
        self.rdSHA256_1.setText(_translate("Hashing_Algorithms_MainWindow", "SHA 256"))
        self.rdSHA512_1.setText(_translate("Hashing_Algorithms_MainWindow", "SHA 512"))
        self.rdBlake2b_1.setText(_translate("Hashing_Algorithms_MainWindow", "Blake2b"))
        self.rdBlake2s_1.setText(_translate("Hashing_Algorithms_MainWindow", "Blake2s"))
        self.rdArgon2_1.setText(_translate("Hashing_Algorithms_MainWindow", "Argon2"))
        self.rdCRC32_1.setText(_translate("Hashing_Algorithms_MainWindow", "CRC32"))
        self.grpBox_AlgorithmTest.setTitle(_translate("Hashing_Algorithms_MainWindow", "Select Algorithm from left side to test"))
        self.btnDecrypt.setText(_translate("Hashing_Algorithms_MainWindow", "Decrypt"))
        self.btnEncrypt.setText(_translate("Hashing_Algorithms_MainWindow", "Encrypt"))
        self.btnCompare.setText(_translate("Hashing_Algorithms_MainWindow", "Compare Algorithms"))
        self.lblMemoryUsage.setText(_translate("Hashing_Algorithms_MainWindow", "Memory Usage"))
        self.lblPerformance_2.setText(_translate("Hashing_Algorithms_MainWindow", "Hash Algorithms"))
        self.lblSecurity.setText(_translate("Hashing_Algorithms_MainWindow", "Frequency Analysis"))
        self.lblPerformance.setText(_translate("Hashing_Algorithms_MainWindow", "Performance"))
        self.grpBox_Algorithm2.setTitle(_translate("Hashing_Algorithms_MainWindow", "Select Algorithm 2"))
        self.rdMD5_2.setText(_translate("Hashing_Algorithms_MainWindow", "MD5"))
        self.rdSHA1_2.setText(_translate("Hashing_Algorithms_MainWindow", "SHA 1"))
        self.rdSHA256_2.setText(_translate("Hashing_Algorithms_MainWindow", "SHA 256"))
        self.rdSHA512_2.setText(_translate("Hashing_Algorithms_MainWindow", "SHA 512"))
        self.rdBlake2b_2.setText(_translate("Hashing_Algorithms_MainWindow", "Blake2b"))
        self.rdBlake2s_2.setText(_translate("Hashing_Algorithms_MainWindow", "Blake2s"))
        self.rdArgon2_2.setText(_translate("Hashing_Algorithms_MainWindow", "Argon2"))
        self.rdCRC32_2.setText(_translate("Hashing_Algorithms_MainWindow", "CRC32"))
    
    def reset_form(self):
        self.rdMD5_1.setChecked(False)
        self.rdSHA1_1.setChecked(False)
        self.rdSHA256_1.setChecked(False)
        self.rdSHA512_1.setChecked(False)
        self.rdBlake2b_1.setChecked(False)
        self.rdBlake2s_1.setChecked(False)
        self.rdArgon2_1.setChecked(False)
        self.rdCRC32_1.setChecked(False)
        
        self.rdMD5_2.setChecked(False)
        self.rdSHA1_2.setChecked(False)
        self.rdSHA256_2.setChecked(False)
        self.rdSHA512_2.setChecked(False)
        self.rdBlake2b_2.setChecked(False)
        self.rdBlake2s_2.setChecked(False)
        self.rdArgon2_2.setChecked(False)
        self.rdCRC32_2.setChecked(False)
        
        self.txtBoxEncrypt.setText("")
        self.txtBoxDecrypt.setText("Irreversible")
        self.txtBoxKey1.setText("")
        self.txtBoxKey2.setText("")
        
        self.graphMemoryUsage.clear()
        self.graphPerformance.clear()
        self.graphSecurity.clear()


# if __name__ == "__main__":
#     import sys
#     app = QtWidgets.QApplication(sys.argv)
#     Hashing_Algorithms_MainWindow = QtWidgets.QMainWindow()
#     ui = Ui_Hashing_Algorithms_MainWindow()
#     ui.setupUi(Hashing_Algorithms_MainWindow)
#     Hashing_Algorithms_MainWindow.show()
#     sys.exit(app.exec_())
