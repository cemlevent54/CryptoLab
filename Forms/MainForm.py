# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainForm.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1243, 856)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.btnOldEncryption = QtWidgets.QPushButton(self.centralwidget)
        self.btnOldEncryption.setGeometry(QtCore.QRect(130, 150, 301, 61))
        
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnOldEncryption.setFont(font)
        self.btnOldEncryption.setStyleSheet("")
        self.btnOldEncryption.setObjectName("btnOldEncryption")
        self.btnSymmetricEncryption = QtWidgets.QPushButton(self.centralwidget)
        self.btnSymmetricEncryption.setGeometry(QtCore.QRect(130, 250, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnSymmetricEncryption.setFont(font)
        self.btnSymmetricEncryption.setStyleSheet("")
        self.btnSymmetricEncryption.setObjectName("btnSymmetricEncryption")
        self.btnAsymmetricEncryption = QtWidgets.QPushButton(self.centralwidget)
        self.btnAsymmetricEncryption.setGeometry(QtCore.QRect(130, 350, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnAsymmetricEncryption.setFont(font)
        self.btnAsymmetricEncryption.setStyleSheet("")
        self.btnAsymmetricEncryption.setObjectName("btnAsymmetricEncryption")
        self.btnHashingAlgorithms = QtWidgets.QPushButton(self.centralwidget)
        self.btnHashingAlgorithms.setGeometry(QtCore.QRect(510, 150, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnHashingAlgorithms.setFont(font)
        self.btnHashingAlgorithms.setStyleSheet("")
        self.btnHashingAlgorithms.setObjectName("btnHashingAlgorithms")
        self.btnHybridAlgorithms = QtWidgets.QPushButton(self.centralwidget)
        self.btnHybridAlgorithms.setGeometry(QtCore.QRect(880, 150, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnHybridAlgorithms.setFont(font)
        self.btnHybridAlgorithms.setStyleSheet("")
        self.btnHybridAlgorithms.setObjectName("btnHybridAlgorithms")
        self.btnModernAlgorithms = QtWidgets.QPushButton(self.centralwidget)
        self.btnModernAlgorithms.setGeometry(QtCore.QRect(880, 250, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnModernAlgorithms.setFont(font)
        self.btnModernAlgorithms.setStyleSheet("")
        self.btnModernAlgorithms.setObjectName("btnModernAlgorithms")
        self.btnQuantumAlgorithms = QtWidgets.QPushButton(self.centralwidget)
        self.btnQuantumAlgorithms.setGeometry(QtCore.QRect(880, 350, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnQuantumAlgorithms.setFont(font)
        self.btnQuantumAlgorithms.setStyleSheet("")
        self.btnQuantumAlgorithms.setObjectName("btnQuantumAlgorithms")
        self.lblTop = QtWidgets.QLabel(self.centralwidget)
        self.lblTop.setGeometry(QtCore.QRect(270, 40, 721, 71))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(20)
        self.lblTop.setFont(font)
        self.lblTop.setObjectName("lblTop")
        self.btnSymmetrivsAsymmetric = QtWidgets.QPushButton(self.centralwidget)
        self.btnSymmetrivsAsymmetric.setGeometry(QtCore.QRect(280, 530, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnSymmetrivsAsymmetric.setFont(font)
        self.btnSymmetrivsAsymmetric.setStyleSheet("")
        self.btnSymmetrivsAsymmetric.setObjectName("btnSymmetrivsAsymmetric")
        self.btnSymmetrivsHybrid = QtWidgets.QPushButton(self.centralwidget)
        self.btnSymmetrivsHybrid.setGeometry(QtCore.QRect(280, 620, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnSymmetrivsHybrid.setFont(font)
        self.btnSymmetrivsHybrid.setStyleSheet("")
        self.btnSymmetrivsHybrid.setObjectName("btnSymmetrivsHybrid")
        self.btnModernvsQuantum = QtWidgets.QPushButton(self.centralwidget)
        self.btnModernvsQuantum.setGeometry(QtCore.QRect(740, 620, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnModernvsQuantum.setFont(font)
        self.btnModernvsQuantum.setStyleSheet("")
        self.btnModernvsQuantum.setObjectName("btnModernvsQuantum")
        self.btnModernvsQuantum_ = QtWidgets.QPushButton(self.centralwidget)
        self.btnModernvsQuantum_.setGeometry(QtCore.QRect(740, 530, 301, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.btnModernvsQuantum_.setFont(font)
        self.btnModernvsQuantum_.setStyleSheet("")
        self.btnModernvsQuantum_.setObjectName("btnModernvsQuantum_")
        self.btnModernAlgorithms.raise_()
        self.btnHashingAlgorithms.raise_()
        self.btnSymmetricEncryption.raise_()
        self.btnQuantumAlgorithms.raise_()
        self.btnAsymmetricEncryption.raise_()
        self.btnOldEncryption.raise_()
        self.btnHybridAlgorithms.raise_()
        self.lblTop.raise_()
        self.btnSymmetrivsAsymmetric.raise_()
        self.btnSymmetrivsHybrid.raise_()
        self.btnModernvsQuantum.raise_()
        self.btnModernvsQuantum_.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1243, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.btnOldEncryption.setText(_translate("MainWindow", "Old Encryption Algorithms"))
        self.btnSymmetricEncryption.setText(_translate("MainWindow", "Symmetric Encryption Algorithms"))
        self.btnAsymmetricEncryption.setText(_translate("MainWindow", "Asymmetric Encryption Algorithms"))
        self.btnHashingAlgorithms.setText(_translate("MainWindow", "Hashing Algorithms"))
        self.btnHybridAlgorithms.setText(_translate("MainWindow", "Hybrid Algorithms"))
        self.btnModernAlgorithms.setText(_translate("MainWindow", "Modern Encryption Algorithms"))
        self.btnQuantumAlgorithms.setText(_translate("MainWindow", "Quantum Encryption Algorithms"))
        self.lblTop.setText(_translate("MainWindow", "Comparison of Current Encryption Algorithms"))
        self.btnSymmetrivsAsymmetric.setText(_translate("MainWindow", "Simetrik vs Asimetrik"))
        self.btnSymmetrivsHybrid.setText(_translate("MainWindow", "Simetrik vs Hybrid"))
        self.btnModernvsQuantum.setText(_translate("MainWindow", "Modern vs Quantum"))
        self.btnModernvsQuantum_.setText(_translate("MainWindow", "Modern vs Old"))
        


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
