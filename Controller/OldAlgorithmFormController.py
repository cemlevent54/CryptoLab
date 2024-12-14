from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QMessageBox, QGraphicsScene
from matplotlib import pyplot as plt
from Forms.OldAlgorithms import Ui_Old_Encryption_MainWindow
from OldAlgorithms.OldEncryptionAlgorithms import OldEncryptionAlgorithms , DecryptionAlgorithms
from CompareAlgorithms.CompareAlgorithms import AlgorithmComparator

from Helpers.FormHelper import FormHelper

form_helper = FormHelper()

class OldEncryption(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(OldEncryption, self).__init__()
        self.ui = Ui_Old_Encryption_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent

        # Algoritma karşılaştırma butonuna olay bağlama
        self.ui.btnCompare.clicked.connect(self.compare_algorithms)
        self.ui.btnEncrypt.clicked.connect(self.btn_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.btn_decrypt)

    def closeEvent(self, event):
        # Pencere kapanırken ana pencereyi yeniden göster
        if self.parent:
            self.parent.show()
        event.accept()

    def get_selected_algorithm(self, groupbox):
        """Seçili algoritmayı bulur"""
        for child in groupbox.findChildren(QtWidgets.QRadioButton):
            if child.isChecked():
                return child.text()  # Seçili RadioButton'un metnini döndür
        return None

    

    def compare_algorithms(self):
        """Seçili algoritmaları karşılaştırır ve sonuçları grafiklere aktarır"""
        selected_algorithm_1 = self.get_selected_algorithm(self.ui.grpBox1)
        selected_algorithm_2 = self.get_selected_algorithm(self.ui.grpBox2)

        if not selected_algorithm_1 or not selected_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return

        algorithm_map = {
            "Caesar Cipher": lambda text: OldEncryptionAlgorithms().caesar_cipher(text, shift=3),
            "Vigenere Cipher": lambda text: OldEncryptionAlgorithms().vigenere_cipher(text, key="AYUSH"),
            "Substitution Cipher": lambda text: OldEncryptionAlgorithms().substitution_cipher(text, key="QWERTYUIOPASDFGHJKLZXCVBNM"),
            "Transposition Cipher": lambda text: OldEncryptionAlgorithms().transposition_cipher(text, key=5),
            "Playfair Cipher": lambda text: OldEncryptionAlgorithms().playfair_cipher(text, key="KEYWORD"),
            "Enigma Machine": lambda text: OldEncryptionAlgorithms().enigma_machine(text, key="ROTOR"),
        }

        algo1 = algorithm_map.get(selected_algorithm_1)
        algo2 = algorithm_map.get(selected_algorithm_2)

        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return

        comparator = AlgorithmComparator(algo1, algo2)
        test_data = "exampledatafortestingalgorithms"
        key_space = 2 ** 16
        comparison_results = comparator.compare_algorithms(test_data, key_space)

        # Performans verileri
        categories = ["Performance", "Frequency", "Brute Force Time", "Memory Usage"]
        data1 = [
            comparison_results["algo1_performance"],
            comparison_results["algo1_frequency"],
            comparison_results["algo1_memory"],
        ]
        data2 = [
            comparison_results["algo2_performance"],
            comparison_results["algo2_frequency"],
            comparison_results["algo2_memory"],
        ]

        # Performans grafiği
        
        form_helper.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])
        # Güvenlik grafiği
       
        form_helper.plot_to_graphicsview(self.ui.graphSecurity, "Security with Frequency Analysis", [data1[1]], [data2[1]], ["Frequency"])
        # Bellek kullanımı grafiği
        
        form_helper.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])
        
        
    
    
    def btn_encrypt(self):
        # Get data from textbox
        text = self.ui.txtBoxEncrypt.toPlainText()

        # Get key from textbox or use default
        caesar_key_input = self.ui.txtBoxKey1.toPlainText()
        caesar_key = int(caesar_key_input) if caesar_key_input.isdigit() else 3  # Default key: 3

        vigenere_key = self.ui.txtBoxKey1.toPlainText() or "AYUSH"  # Default key: "AYUSH"
        substitution_key = self.ui.txtBoxKey1.toPlainText() or "QWERTYUIOPASDFGHJKLZXCVBNM"  # Default key: "QWERTY..."
        transposition_key_input = self.ui.txtBoxKey1.toPlainText()
        transposition_key = int(transposition_key_input) if transposition_key_input.isdigit() else 5  # Default key: 5
        playfair_key = self.ui.txtBoxKey1.toPlainText() or "KEYWORD"  # Default key: "KEYWORD"
        enigma_key = self.ui.txtBoxKey1.toPlainText() or "ROTOR"  # Default key: "ROTOR"

        # Get selected algorithm
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox1)

        # Get algorithm map
        algorithm_map = {
            "Caesar Cipher": lambda text: OldEncryptionAlgorithms().caesar_cipher(text, shift=caesar_key),
            "Vigenere Cipher": lambda text: OldEncryptionAlgorithms().vigenere_cipher(text, key=vigenere_key),
            "Substitution Cipher": lambda text: OldEncryptionAlgorithms().substitution_cipher(text, key=substitution_key),
            "Transposition Cipher": lambda text: OldEncryptionAlgorithms().transposition_cipher(text, key=transposition_key),
            "Playfair Cipher": lambda text: OldEncryptionAlgorithms().playfair_cipher(text, key=playfair_key),
            "Enigma Machine": lambda text: OldEncryptionAlgorithms().enigma_machine(text, key=enigma_key),
        }

        # Get selected algorithm function
        algo = algorithm_map.get(selected_algorithm)
        if not algo:
            self.ui.txtBoxDecrypt.setText("Invalid algorithm selected!")
            return

        # Get encrypted text
        encrypted_text = algo(text)

        # Set encrypted text to textbox
        self.ui.txtBoxDecrypt.setText(encrypted_text)
        self.ui.txtBoxEncrypt.setText("")
        self.ui.txtBoxKey1.setText("")

    def btn_decrypt(self):
        # Get data from textbox
        text = self.ui.txtBoxDecrypt.toPlainText()

        # Get key from textbox or use default
        caesar_key_input = self.ui.txtBoxKey2.toPlainText()
        caesar_key = int(caesar_key_input) if caesar_key_input.isdigit() else 3  # Default key: 3

        vigenere_key = self.ui.txtBoxKey2.toPlainText() or "AYUSH"  # Default key: "AYUSH"
        substitution_key = self.ui.txtBoxKey2.toPlainText() or "QWERTYUIOPASDFGHJKLZXCVBNM"  # Default key: "QWERTY..."
        transposition_key_input = self.ui.txtBoxKey2.toPlainText()
        transposition_key = int(transposition_key_input) if transposition_key_input.isdigit() else 5  # Default key: 5
        playfair_key = self.ui.txtBoxKey2.toPlainText() or "KEYWORD"  # Default key: "KEYWORD"
        enigma_key = self.ui.txtBoxKey2.toPlainText() or "ROTOR"  # Default key: "ROTOR"

        # Get selected algorithm
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox1)

        # Get algorithm map
        algorithm_map = {
            "Caesar Cipher": lambda text: DecryptionAlgorithms().caesar_cipher(text, shift=caesar_key),
            "Vigenere Cipher": lambda text: DecryptionAlgorithms().vigenere_cipher(text, key=vigenere_key),
            "Substitution Cipher": lambda text: DecryptionAlgorithms().substitution_cipher(text, key=substitution_key),
            "Transposition Cipher": lambda text: DecryptionAlgorithms().transposition_cipher(text, key=transposition_key),
            "Playfair Cipher": lambda text: DecryptionAlgorithms().playfair_cipher(text, key=playfair_key),
            "Enigma Machine": lambda text: DecryptionAlgorithms().enigma_machine(text, key=enigma_key),
        }

        # Get selected algorithm function
        algo = algorithm_map.get(selected_algorithm)
        if not algo:
            self.ui.txtBoxEncrypt.setText("Invalid algorithm selected!")
            return

        # Get decrypted text
        decrypted_text = algo(text)

        # Set decrypted text to textbox
        self.ui.txtBoxEncrypt.setText(decrypted_text)
        self.ui.txtBoxDecrypt.setText("")
        self.ui.txtBoxKey2.setText("")
