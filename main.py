import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
from Forms.MainForm import Ui_MainWindow

# Controller importları
from Controller.OldAlgorithmFormController import OldEncryption
from Controller.SymmetricAlgorithmFormController import SymmetricEncryption
from Controller.AsymmetricAlgorithmFormController import AsymmetricEncryption
from Controller.HybridAlgorithmFormController import CompositeEncryption
from Controller.ModernAlgorithmFormController import ModernEncryption
from Controller.QuantumAlgorithmFormController import QuantumEncryption
from Controller.HashAlgorithmFormController import HashAlgorithms
from Controller.SymmetricVsAsymmetricFormController import SymmetricvsAsymmetric
from Controller.SymmetricVsHybridFormController import SymmetricvsHybrid
from Controller.ModernVsOldFormController import ModernvsOld


class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Buton bağlantıları
        self.ui.btnOldEncryption.clicked.connect(self.openOldEncryption)
        self.ui.btnSymmetricEncryption.clicked.connect(self.openSymmetricEncryption)
        self.ui.btnAsymmetricEncryption.clicked.connect(self.openAsymmetricEncryption)
        self.ui.btnHybridAlgorithms.clicked.connect(self.openCompositeEncryption)
        self.ui.btnModernAlgorithms.clicked.connect(self.openModernEncryption)
        self.ui.btnQuantumAlgorithms.clicked.connect(self.openQuantumEncryption)
        self.ui.btnHashingAlgorithms.clicked.connect(self.openHashingAlgorithms)
        self.ui.btnSymmetrivsAsymmetric.clicked.connect(self.openSymmetricVsAsymmetricAlgorithms)
        self.ui.btnSymmetrivsHybrid.clicked.connect(self.openSymmetricVsCompositeAlgorithms)
        self.ui.btnModernvsOld.clicked.connect(self.openModernVsOldAlgorithms)

    # Fonksiyonlar
    def openOldEncryption(self):
        self.oldEncryption = OldEncryption(self)
        self.oldEncryption.show()
        self.hide()

    def openSymmetricEncryption(self):
        self.symmetricEncryption = SymmetricEncryption(self)
        self.symmetricEncryption.show()
        self.hide()

    def openAsymmetricEncryption(self):
        self.asymmetricEncryption = AsymmetricEncryption(self)
        self.asymmetricEncryption.show()
        self.hide()

    def openCompositeEncryption(self):
        self.compositeEncryption = CompositeEncryption(self)
        self.compositeEncryption.show()
        self.hide()

    def openModernEncryption(self):
        self.modernEncryption = ModernEncryption(self)
        self.modernEncryption.show()
        self.hide()

    def openQuantumEncryption(self):
        self.quantumEncryption = QuantumEncryption(self)
        self.quantumEncryption.show()
        self.hide()

    def openHashingAlgorithms(self):
        self.hashingAlgorithms = HashAlgorithms(self)
        self.hashingAlgorithms.show()
        self.hide()

    def openSymmetricVsAsymmetricAlgorithms(self):
        self.SymmetricvsAsymmetricAlgorithms = SymmetricvsAsymmetric(self)
        self.SymmetricvsAsymmetricAlgorithms.show()
        self.hide()

    def openSymmetricVsCompositeAlgorithms(self):
        self.SymmetricvsCompositeAlgorithms = SymmetricvsHybrid(self)
        self.SymmetricvsCompositeAlgorithms.show()
        self.hide()

    def openModernVsOldAlgorithms(self):
        self.ModernvsOldAlgorithms = ModernvsOld(self)
        self.ModernvsOldAlgorithms.show()
        self.hide()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec_())
