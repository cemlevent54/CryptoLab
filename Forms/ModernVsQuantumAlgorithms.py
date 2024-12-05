# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ModernVsQuantumAlgorithms.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Modern_Quantum_MainWindow(object):
    def setupUi(self, Modern_Quantum_MainWindow):
        Modern_Quantum_MainWindow.setObjectName("Modern_Quantum_MainWindow")
        Modern_Quantum_MainWindow.resize(1244, 854)
        self.centralwidget = QtWidgets.QWidget(Modern_Quantum_MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.lblMemoryUsage = QtWidgets.QLabel(self.centralwidget)
        self.lblMemoryUsage.setGeometry(QtCore.QRect(960, 140, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblMemoryUsage.setFont(font)
        self.lblMemoryUsage.setObjectName("lblMemoryUsage")
        self.grpBox_Algorithm2 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm2.setGeometry(QtCore.QRect(40, 450, 311, 331))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm2.setFont(font)
        self.grpBox_Algorithm2.setObjectName("grpBox_Algorithm2")
        self.rdLattice = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdLattice.setGeometry(QtCore.QRect(10, 40, 281, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdLattice.setFont(font)
        self.rdLattice.setObjectName("rdLattice")
        self.rdHash = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdHash.setGeometry(QtCore.QRect(10, 110, 271, 20))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.rdHash.setFont(font)
        self.rdHash.setObjectName("rdHash")
        self.rdCode = QtWidgets.QRadioButton(self.grpBox_Algorithm2)
        self.rdCode.setGeometry(QtCore.QRect(10, 180, 281, 20))
        self.rdCode.setObjectName("rdCode")
        self.lblSecurity = QtWidgets.QLabel(self.centralwidget)
        self.lblSecurity.setGeometry(QtCore.QRect(970, 440, 181, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblSecurity.setFont(font)
        self.lblSecurity.setObjectName("lblSecurity")
        self.btnCompare = QtWidgets.QPushButton(self.centralwidget)
        self.btnCompare.setGeometry(QtCore.QRect(550, 470, 211, 51))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.btnCompare.setFont(font)
        self.btnCompare.setObjectName("btnCompare")
        self.graphSecurity = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphSecurity.setGeometry(QtCore.QRect(910, 480, 271, 221))
        self.graphSecurity.setObjectName("graphSecurity")
        self.grpBox_Algorithm1 = QtWidgets.QGroupBox(self.centralwidget)
        self.grpBox_Algorithm1.setGeometry(QtCore.QRect(40, 80, 311, 321))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.grpBox_Algorithm1.setFont(font)
        self.grpBox_Algorithm1.setObjectName("grpBox_Algorithm1")
        self.rdAESGCM = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdAESGCM.setGeometry(QtCore.QRect(10, 60, 371, 31))
        self.rdAESGCM.setObjectName("rdAESGCM")
        self.rdRSAPSS = QtWidgets.QRadioButton(self.grpBox_Algorithm1)
        self.rdRSAPSS.setGeometry(QtCore.QRect(10, 120, 281, 20))
        self.rdRSAPSS.setObjectName("rdRSAPSS")
        self.graphPerformance = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphPerformance.setGeometry(QtCore.QRect(540, 180, 271, 221))
        self.graphPerformance.setObjectName("graphPerformance")
        self.lblHeader = QtWidgets.QLabel(self.centralwidget)
        self.lblHeader.setGeometry(QtCore.QRect(430, 20, 461, 61))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.lblHeader.setFont(font)
        self.lblHeader.setObjectName("lblHeader")
        self.graphMemoryUsage = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphMemoryUsage.setGeometry(QtCore.QRect(910, 180, 271, 221))
        self.graphMemoryUsage.setObjectName("graphMemoryUsage")
        self.lblPerformance = QtWidgets.QLabel(self.centralwidget)
        self.lblPerformance.setGeometry(QtCore.QRect(620, 140, 121, 31))
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lblPerformance.setFont(font)
        self.lblPerformance.setObjectName("lblPerformance")
        Modern_Quantum_MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Modern_Quantum_MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1244, 26))
        self.menubar.setObjectName("menubar")
        Modern_Quantum_MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Modern_Quantum_MainWindow)
        self.statusbar.setObjectName("statusbar")
        Modern_Quantum_MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(Modern_Quantum_MainWindow)
        QtCore.QMetaObject.connectSlotsByName(Modern_Quantum_MainWindow)

    def retranslateUi(self, Modern_Quantum_MainWindow):
        _translate = QtCore.QCoreApplication.translate
        Modern_Quantum_MainWindow.setWindowTitle(_translate("Modern_Quantum_MainWindow", "MainWindow"))
        self.lblMemoryUsage.setText(_translate("Modern_Quantum_MainWindow", "Memory Usage"))
        self.grpBox_Algorithm2.setTitle(_translate("Modern_Quantum_MainWindow", "Select Algorithm 2"))
        self.rdLattice.setText(_translate("Modern_Quantum_MainWindow", "Lattice Based Cryptography"))
        self.rdHash.setText(_translate("Modern_Quantum_MainWindow", "Hash Based Cryptography"))
        self.rdCode.setText(_translate("Modern_Quantum_MainWindow", "Code Based Cryptography"))
        self.lblSecurity.setText(_translate("Modern_Quantum_MainWindow", "Frequency Analysis"))
        self.btnCompare.setText(_translate("Modern_Quantum_MainWindow", "Compare Algorithms"))
        self.grpBox_Algorithm1.setTitle(_translate("Modern_Quantum_MainWindow", "Select Algorithm 1 "))
        self.rdAESGCM.setText(_translate("Modern_Quantum_MainWindow", "AES - GCM"))
        self.rdRSAPSS.setText(_translate("Modern_Quantum_MainWindow", "RSA - PSS"))
        self.lblHeader.setText(_translate("Modern_Quantum_MainWindow", "Modern vs Quantum Algorithms"))
        self.lblPerformance.setText(_translate("Modern_Quantum_MainWindow", "Performance"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Modern_Quantum_MainWindow = QtWidgets.QMainWindow()
    ui = Ui_Modern_Quantum_MainWindow()
    ui.setupUi(Modern_Quantum_MainWindow)
    Modern_Quantum_MainWindow.show()
    sys.exit(app.exec_())