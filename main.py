import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QGraphicsScene
from PyQt5.QtGui import QPixmap
from PyQt5 import QtWidgets

from Crypto.Cipher import DES3

import matplotlib.pyplot as plt

from Forms.MainForm import Ui_MainWindow
from Forms.OldAlgorithms import Ui_Old_Encryption_MainWindow
from Forms.SymmetricEncryptionAlgorithms import Ui_SymmetricEncryption_MainWindow
from Forms.AsymmetricEncryptionAlgorithms import Ui_Asymmetic_Encryption_MainWindow


from AsymmetricAlgorithms.AsymmetricDecryptionAlgorithms import AsymmetricDecryptionAlgorithms
from AsymmetricAlgorithms.AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms
from SymmetricAlgorithms.SymmetricDecryptionAlgorithms import SymmetricDecryptionAlgorithms
from CompareAlgorithms.CompareAlgorithms import AlgorithmComparator
from OldAlgorithms.OldEncryptionAlgorithms import OldEncryptionAlgorithms, DecryptionAlgorithms
from SymmetricAlgorithms.SymmetricEncryptionAlgorithms import SymmetricEncryptionAlgorithms
# define qcore
import PyQt5.QtCore as QtCore
from base64 import encode, decode
#comparison
from CompareAlgorithms.CompareSymmetricAlgorithms import SymmetricAlgorithmComparator
from CompareAlgorithms.CompareAsymmetricAlgorithms import AsymmetricAlgorithmComparator

# for generating key
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes
import os


class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Eski şifreleme penceresi için butona olay bağlama
        self.ui.btnOldEncryption.clicked.connect(self.openOldEncryption)
        self.ui.btnSymmetricEncryption.clicked.connect(self.openSymmetricEncryption)
        self.ui.btnAsymmetricEncryption.clicked.connect(self.openAsymmetricEncryption)

    def openOldEncryption(self):
        # Eski şifreleme penceresini başlat ve göster
        self.oldEncryption = OldEncryption(self)
        self.oldEncryption.show()
        self.hide()
        
    def openSymmetricEncryption(self):
        # Simetrik şifreleme penceresini başlat ve göster
        self.symmetricEncryption = SymmetricEncryption(self)
        self.symmetricEncryption.show()
        self.hide()
    
    def openAsymmetricEncryption(self):
        # Asimetrik şifreleme penceresini başlat ve göster
        self.asymmetricEncryption = AsymmetricEncryption(self)
        self.asymmetricEncryption.show()
        self.hide()


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

    def plot_to_graphicsview(self, graphics_view, title, data1, data2, categories):
        """
        Matplotlib grafiğini QGraphicsView içinde göstermek için.
        :param graphics_view: QGraphicsView bileşeni.
        :param title: Grafik başlığı.
        :param data1: Birinci algoritmanın verileri.
        :param data2: İkinci algoritmanın verileri.
        :param categories: Kategoriler (örneğin: Performans, Güvenlik).
        """
        # Matplotlib grafiğini oluştur
        plt.figure(figsize=(3.5, 2.5))  # QGraphicsView boyutuna uygun bir boyut seç
        x = range(len(categories))
        plt.bar(x, data1, width=0.2, label="Algorithm 1", align="center")
        plt.bar([p + 0.4 for p in x], data2, width=0.2, label="Algorithm 2", align="center")
        plt.xticks([p + 0.2 for p in x], categories)
        plt.xlabel("Metrics")
        plt.ylabel("Scores")
        plt.title(title)
        plt.legend()
        plt.tight_layout()  # Kenar boşluklarını azalt

        # Geçici bir PNG dosyasına kaydet
        temp_file = "temp_graph.png"
        plt.savefig(temp_file, dpi=100)  # DPI'ı düşürerek görüntüye daha fazla yer kazandırabilirsiniz
        plt.close()

        # QGraphicsView içine yükle
        scene = QGraphicsScene()
        pixmap = QPixmap(temp_file)
        scene.addPixmap(pixmap)
        graphics_view.setScene(scene)

        # QGraphicsView içindeki görüntüyü tam boyutta göster
        graphics_view.fitInView(scene.itemsBoundingRect(), QtCore.Qt.KeepAspectRatio)

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
        self.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])

        # Güvenlik grafiği
        self.plot_to_graphicsview(self.ui.graphSecurity, "Security with Frequency Analysis", [data1[1]], [data2[1]], ["Frequency"])

        # Bellek kullanımı grafiği
        self.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])

    def log_comparisons(self):
        """Karşılaştırma sonuçlarını konsola yazdırır"""
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

        print("Algorithm Comparison Results:")
        print(f"Performance: {comparison_results['algo1_performance']} vs {comparison_results['algo2_performance']}")
        print(f"Frequency Analysis: {comparison_results['algo1_frequency']} vs {comparison_results['algo2_frequency']}")
        print(f"Memory Usage: {comparison_results['algo1_memory']} vs {comparison_results['algo2_memory']}")
    
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


class SymmetricEncryption(QtWidgets.QMainWindow):
    encryption_keys = {}
    def __init__(self,parent=None):
        super(SymmetricEncryption, self).__init__()
        self.ui = Ui_SymmetricEncryption_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
        # Algoritma karşılaştırma butonuna olay bağlama
        self.ui.btnCompare.clicked.connect(self.compare_algorithms)
        # self.ui.btnLog.clicked.connect(self.log_comparisons)
        self.ui.btnEncrypt.clicked.connect(self.btn_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.btn_decrypt)
        
    def closeEvent(self,event):
        if self.parent:
            self.parent.show()
        event.accept()
    
    def get_selected_algorithm(self, groupbox):
        """Seçili algoritmayı bulur"""
        for child in groupbox.findChildren(QtWidgets.QRadioButton):
            if child.isChecked():
                return child.text()  # Seçili RadioButton'un metnini döndür
        return None
    
    def plot_to_graphicsview(self, graphics_view, title, data1, data2, categories):
        """
        Matplotlib grafiğini QGraphicsView içinde göstermek için.
        :param graphics_view: QGraphicsView bileşeni.
        :param title: Grafik başlığı.
        :param data1: Birinci algoritmanın verileri.
        :param data2: İkinci algoritmanın verileri.
        :param categories: Kategoriler (örneğin: Performans, Güvenlik).
        """
        
        plt.figure(figsize=(3.5, 2.5))  # QGraphicsView boyutuna uygun bir boyut seç
        x = range(len(categories))
        plt.bar(x, data1, width=0.2, label="Algorithm 1", align="center")
        plt.bar([p + 0.4 for p in x], data2, width=0.2, label="Algorithm 2", align="center")
        plt.xticks([p + 0.2 for p in x], categories)
        plt.xlabel("Metrics")
        plt.ylabel("Scores")
        plt.title(title)
        plt.legend()
        plt.tight_layout()
        
        temp_file = "temp_graph.png"
        plt.savefig(temp_file, dpi=100)
        plt.close()
        
        scene = QGraphicsScene()
        pixmap = QPixmap(temp_file)
        scene.addPixmap(pixmap)
        graphics_view.setScene(scene)
        
        graphics_view.fitInView(scene.itemsBoundingRect(), QtCore.Qt.KeepAspectRatio)
    
    def compare_algorithms(self):
        """Seçili algoritmaları karşılaştırır ve sonuçları grafiklere aktarır"""
        
        # Algoritma eşleşme haritası
        map_selected_algorithm = {
            "AES(Advanced Encryption Standard)": "AES",
            "DES(Data Encryption Standard)": "DES",
            "3DES(Triple DES)": "3DES",
            "RC4(Rivest Cipher 4)": "RC4",
            "Blowfish": "Blowfish",
            "Twofish": "Twofish",
            "ChaCha20": "ChaCha20",
        }

        # Seçili algoritmaları al
        algorithm_1 = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        algorithm_2 = self.get_selected_algorithm(self.ui.grpBox_Algorithm2)

        # Algoritma adlarını eşleştir
        mapped_algorithm_1 = map_selected_algorithm.get(algorithm_1)
        mapped_algorithm_2 = map_selected_algorithm.get(algorithm_2)

        if not mapped_algorithm_1 or not mapped_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return

        # Algoritma şifreleme haritası ve doğru uzunlukta anahtarlar
        keys = {
            "AES": os.urandom(16),  # AES için 16 bayt
            "DES": os.urandom(8),   # DES için 8 bayt
            "3DES": DES3.adjust_key_parity(os.urandom(24)),  # 3DES için 24 bayt
            "RC4": os.urandom(16),  # RC4 için 16 bayt
            "Blowfish": os.urandom(16),  # Blowfish için 16 bayt
            "Twofish": os.urandom(16),   # Twofish için 16 bayt
            "ChaCha20": os.urandom(32),  # ChaCha20 için 32 bayt
        }

        algorithm_map = {
            "AES": lambda text: SymmetricEncryptionAlgorithms().aes_encrypt(text, key=keys["AES"]),
            "DES": lambda text: SymmetricEncryptionAlgorithms().des_encrypt(text, key=keys["DES"]),
            "3DES": lambda text: SymmetricEncryptionAlgorithms().des3_encrypt(text, key=keys["3DES"]),
            "RC4": lambda text: SymmetricEncryptionAlgorithms().rc4_encrypt(text, key=keys["RC4"]),
            "Blowfish": lambda text: SymmetricEncryptionAlgorithms().blowfish_encrypt(text, key=keys["Blowfish"]),
            "Twofish": lambda text: SymmetricEncryptionAlgorithms().twofish_encrypt(text, key=keys["Twofish"]),
            "ChaCha20": lambda text: SymmetricEncryptionAlgorithms().chacha20_encrypt(text, key=keys["ChaCha20"]),
        }

        # Algoritma fonksiyonlarını alın
        algo1 = algorithm_map.get(mapped_algorithm_1)
        algo2 = algorithm_map.get(mapped_algorithm_2)

        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return

        # Algoritma karşılaştırma işlemi
        comparator = SymmetricAlgorithmComparator(algo1, algo2)
        test_data = "exampledatafortestingalgorithms" * 300
        key_space = 2 ** 16
        comparison_results = comparator.compare_algorithms(test_data, key_space)

        # Karşılaştırma sonuçlarını kategorilere ayır
        categories = ["Performance", "Frequency", "Memory Usage"]
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
        self.plot_to_graphicsview(
            self.ui.graphPerformance,
            "Performance Comparison",
            [data1[0]],
            [data2[0]],
            ["Performance"],
        )

        # Güvenlik grafiği
        self.plot_to_graphicsview(
            self.ui.graphSecurity,
            "Security with Frequency Analysis",
            [data1[1]],
            [data2[1]],
            ["Frequency"],
        )

        # Bellek kullanımı grafiği
        self.plot_to_graphicsview(
            self.ui.graphMemoryUsage,
            "Memory Usage",
            [data1[2]],
            [data2[2]],
            ["Memory"],
        )

        
    def log_comparisons(self):
        """
        Karşılaştırma sonuçlarını konsola yazdırır
        """
        selected_algorithm_1 = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        selected_algorithm_2 = self.get_selected_algorithm(self.ui.grpBox_Algorithm2)
        
        if not selected_algorithm_1 or not selected_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return
        
        algorithm_map = {
            "AES": lambda text: SymmetricEncryptionAlgorithms().aes_encrypt(text, key="key"),
            "DES": lambda text: SymmetricEncryptionAlgorithms().des_encrypt(text, key="key"),
            "3DES": lambda text: SymmetricEncryptionAlgorithms().des3_encrypt(text, key="key"),
            "RC4": lambda text: SymmetricEncryptionAlgorithms().rc4_encrypt(text, key="key"),
            "Blowfish": lambda text: SymmetricEncryptionAlgorithms().blowfish_encrypt(text, key="key"),
            "Twofish": lambda text: SymmetricEncryptionAlgorithms().twofish_encrypt(text, key="key"),
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
        
        print("Algorithm Comparison Results:")
        print(f"Performance: {comparison_results['algo1_performance']} vs {comparison_results['algo2_performance']}")
        print(f"Frequency Analysis: {comparison_results['algo1_frequency']} vs {comparison_results['algo2_frequency']}")
        print(f"Memory Usage: {comparison_results['algo1_memory']} vs {comparison_results['algo2_memory']}")
        print("----------------------------------------")
    
    def btn_encrypt(self):
        """Şifreleme işlemini gerçekleştirir"""
        # Şifreleme metnini al
        text = self.ui.txtBoxEncrypt.toPlainText()

        # Anahtar oluşturma
        keys = {
            "AES": os.urandom(16),  # AES Key (128 bits)
            "DES": os.urandom(8),   # DES Key (64 bits)
            "3DES": DES3.adjust_key_parity(os.urandom(24)),  # 3DES Key (192 bits)
            "RC4": os.urandom(16),  # RC4 Key (128 bits)
            "Blowfish": os.urandom(16),  # Blowfish Key (128 bits)
            "Twofish": os.urandom(16),   # Twofish Key (128 bits)
            "ChaCha20": os.urandom(32),  # ChaCha20 Key (256 bits)
        }

        # Seçili algoritmayı alın
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm: {selected_algorithm}")

        # Algoritma eşleştirme haritası
        map_selected_algorithm = {
            "AES(Advanced Encryption Standard)": "AES",
            "DES(Data Encryption Standard)": "DES",
            "3DES(Triple DES)": "3DES",
            "RC4(Rivest Cipher 4)": "RC4",
            "Blowfish": "Blowfish",
            "Twofish": "Twofish",
            "ChaCha20": "ChaCha20",
        }

        # Eşleştirilmiş algoritma adını bulun
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm)
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        print(f"Mapped Algorithm: {mapped_algorithm}")

        # Anahtarı sakla
        key = keys[mapped_algorithm]
        self.encryption_keys[mapped_algorithm] = key
        print(f"Generated Key: {key}")

        # Algoritma haritasını oluştur
        algorithm_map = {
            "AES": lambda text: SymmetricEncryptionAlgorithms().aes_encrypt(text, key),
            "DES": lambda text: SymmetricEncryptionAlgorithms().des_encrypt(text, key),
            "3DES": lambda text: SymmetricEncryptionAlgorithms().des3_encrypt(text, key),
            "RC4": lambda text: SymmetricEncryptionAlgorithms().rc4_encrypt(text, key),
            "Blowfish": lambda text: SymmetricEncryptionAlgorithms().blowfish_encrypt(text, key),
            "Twofish": lambda text: SymmetricEncryptionAlgorithms().twofish_encrypt(text, key),
            "ChaCha20": lambda text: SymmetricEncryptionAlgorithms().chacha20_encrypt(text, key),
        }

        # Şifreleme işlemini çalıştır
        algo = algorithm_map.get(mapped_algorithm)
        if not algo:
            QMessageBox.warning(self, "Encryption Error", "Invalid algorithm selected!")
            return

        try:
            # Şifreleme işlemi
            encrypted_text = algo(text)
            print(f"Encrypted Text: {encrypted_text}")
            encrypted_text_for_textbox = encrypted_text.decode("latin1")
            # Sonuçları arayüze yazdır
            self.ui.txtBoxDecrypt.setText(encrypted_text_for_textbox)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
        except Exception as e:
            QMessageBox.warning(self, "Encryption Error", f"An error occurred: {e}")
        
    def btn_decrypt(self):
        """Deşifreleme işlemini gerçekleştirir"""
        # Şifrelenmiş metni al
        text = self.ui.txtBoxDecrypt.toPlainText()
        # encode et
        encoded_text = text.encode("latin1")
        text = encoded_text

        # Seçili algoritmayı alın
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm for Decryption: {selected_algorithm}")

        # Algoritma eşleştirme haritası
        map_selected_algorithm = {
            "AES(Advanced Encryption Standard)": "AES",
            "DES(Data Encryption Standard)": "DES",
            "3DES(Triple DES)": "3DES",
            "RC4(Rivest Cipher 4)": "RC4",
            "Blowfish": "Blowfish",
            "Twofish": "Twofish",
            "ChaCha20": "ChaCha20",
        }

        # Eşleştirilmiş algoritma adını bulun
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm)
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return

        # Saklanan anahtarı alın
        key = self.encryption_keys.get(mapped_algorithm)
        if not key:
            QMessageBox.warning(self, "Key Error", "No key found for the selected algorithm!")
            return

        # Algoritma haritasını oluştur
        algorithm_map = {
            "AES": lambda text: SymmetricDecryptionAlgorithms().aes_decrypt(text, key),
            "DES": lambda text: SymmetricDecryptionAlgorithms().des_decrypt(text, key),
            "3DES": lambda text: SymmetricDecryptionAlgorithms().des3_decrypt(text, key),
            "RC4": lambda text: SymmetricDecryptionAlgorithms().rc4_decrypt(text, key),
            "Blowfish": lambda text: SymmetricDecryptionAlgorithms().blowfish_decrypt(text, key),
            "Twofish": lambda text: SymmetricDecryptionAlgorithms().twofish_decrypt(text, key),
            "ChaCha20": lambda text: SymmetricDecryptionAlgorithms().chacha20_decrypt(text, key),
        }

        # Deşifreleme işlemini çalıştır
        algo = algorithm_map.get(mapped_algorithm)
        if not algo:
            QMessageBox.warning(self, "Decryption Error", "Invalid algorithm selected!")
            return

        try:
            # Deşifreleme işlemi
            decrypted_text = algo(text)
            print(f"Decrypted Text: {decrypted_text}")

            # Sonuçları arayüze yazdır
            self.ui.txtBoxEncrypt.setText(decrypted_text)
            self.ui.txtBoxDecrypt.setText("")
            self.ui.txtBoxKey2.setText("")
        except Exception as e:
            QMessageBox.warning(self, "Decryption Error", f"An error occurred: {e}")
        
class AsymmetricEncryption(QtWidgets.QMainWindow):
    encryption_keys = {}
    diffie_hellman_keys = {}
    rsa_encryption_keys = {}
    def __init__(self,parent=None):
        super(AsymmetricEncryption, self).__init__()
        self.ui = Ui_Asymmetic_Encryption_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
        # Algoritma karşılaştırma butonuna olay bağlama
        self.ui.btnEncrypt.clicked.connect(self.btn_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.btn_decrypt)
        self.ui.btnCompare.clicked.connect(self.compare_algorithms)
        
    
    def closeEvent(self,event):
        if self.parent:
            self.parent.show()
        event.accept()
    
    def get_selected_algorithm(self, groupbox):
        """Seçili algoritmaları bulur."""
        for child in groupbox.findChildren(QtWidgets.QRadioButton):
            if child.isChecked():
                return child.text()
        return None
    
    def plot_to_graphicsview(self, graphics_view, title, data1, data2, categories):
        """
        Matplotlib grafiğini QGraphicsView içinde göstermek için.
        :param graphics_view: QGraphicsView bileşeni.
        :param title: Grafik başlığı.
        :param data1: Birinci algoritmanın verileri.
        :param data2: İkinci algoritmanın verileri.
        :param categories: Kategoriler (örneğin: Performans, Güvenlik).
        """
        
        plt.figure(figsize=(3.5, 2.5))  # QGraphicsView boyutuna uygun bir boyut seç
        x = range(len(categories))
        plt.bar(x, data1, width=0.2, label="Algorithm 1", align="center")
        plt.bar([p + 0.4 for p in x], data2, width=0.2, label="Algorithm 2", align="center")
        plt.xticks([p + 0.2 for p in x], categories)
        plt.xlabel("Metrics")
        plt.ylabel("Scores")
        plt.title(title)
        plt.legend()
        plt.tight_layout()
        
        temp_file = "temp_graph.png"
        plt.savefig(temp_file, dpi=100)
        plt.close()
        
        scene = QGraphicsScene()
        pixmap = QPixmap(temp_file)
        scene.addPixmap(pixmap)
        graphics_view.setScene(scene)
        
        graphics_view.fitInView(scene.itemsBoundingRect(), QtCore.Qt.KeepAspectRatio)
        
    def compare_algorithms(self):
        """Seçili algoritmaları karşılaştırır ve sonuçları grafiklere aktarır"""
        
        map_selected_algorithm = {
            "RSA (Rivest–Shamir–Adleman)": "RSA",
            "DSA (Digital Signature Algorithm)": "DSA",
            "Diffie-Hellman Key Exchange": "Diffie-Hellman",
        }
        
        selected_algorithm_1 = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        selected_algorithm_2 = self.get_selected_algorithm(self.ui.grpBox_Algorithm2)
        
        mapped_algorithm_1 = map_selected_algorithm.get(selected_algorithm_1)
        mapped_algorithm_2 = map_selected_algorithm.get(selected_algorithm_2)
        
        if not mapped_algorithm_1 or not mapped_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return
                
        algorithm_map = {
            "RSA": lambda text: AsymmetricEncryptionAlgorithms().rsa_encrypt(text),
            "DSA": lambda text: AsymmetricEncryptionAlgorithms().dsa_encrypt(text),
            "Diffie-Hellman": lambda text: AsymmetricEncryptionAlgorithms().diffie_hellman_text_key_exchange(text),
        }
        
        algo1 = algorithm_map.get(mapped_algorithm_1)
        algo2 = algorithm_map.get(mapped_algorithm_2)
        
        # go to compareasymmetricalgorithms.py and compareresult functions
        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return
        
        comparator = AsymmetricAlgorithmComparator(algo1, algo2)
        test_data = "exampledatafortestingalgorithms" 
        key_space = 2 ** 16
        comparison_results = comparator.compare_algorithms(test_data, key_space)
        
        categories = ["Performance", "Frequency", "Memory Usage"]
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
        
        self.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])
        self.plot_to_graphicsview(self.ui.graphSecurity, "Security with Frequency Analysis", [data1[1]], [data2[1]], ["Frequency"])
        self.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])
        
        
        
    
    def generate_rsa_key(self,key_size=2048):
        """RSA anahtar çifti oluşturur"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        return private_key

    def generate_dsa_key(self,key_size=2048):
        """DSA anahtar çifti oluşturur"""
        private_key = dsa.generate_private_key(
            key_size=key_size,
        )
        return private_key
    
    def btn_encrypt(self):
        """Şifreleme işlemini gerçekleştirir"""
        text = self.ui.txtBoxEncrypt.toPlainText()
        
        generated_rsa_key = self.generate_rsa_key(2048)
        generated_dsa_key = self.generate_dsa_key(2048)
        
        keys = {
            "RSA": generated_rsa_key,
            "DSA": generated_dsa_key,
            # key for diffie hellman
            "Diffie-Hellman": None,
        }
        
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm: {selected_algorithm}")
        
        map_selected_algorithm = {
            "RSA (Rivest–Shamir–Adleman)": "RSA",
            "DSA (Digital Signature Algorithm)": "DSA",
            "Diffie-Hellman Key Exchange": "Diffie-Hellman",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm)
        print(f"Mapped Algorithm: {mapped_algorithm}")
        
        key = keys[mapped_algorithm]
        self.encryption_keys[mapped_algorithm] = key
        
        asymmetric_encryption_algorithms = AsymmetricEncryptionAlgorithms()
        
        algorithm_map = {
            "RSA": lambda text: asymmetric_encryption_algorithms.rsa_encrypt(text),
            "DSA": lambda text: asymmetric_encryption_algorithms.dsa_encrypt(text),
            "Diffie-Hellman": lambda text: asymmetric_encryption_algorithms.diffie_hellman_text_key_exchange(text),
        }
        
        algo = algorithm_map.get(mapped_algorithm)
        if not algo:
            QMessageBox.warning(self, "Encryption Error", "Invalid algorithm selected!")
            return
        
        try:
            if mapped_algorithm == "Diffie-Hellman":
                encrypted_text_result = algo(text)
                print(encrypted_text_result)
                encrypted_text = encrypted_text_result["encrypted_message"]
                shared_secret = encrypted_text_result["shared_secret"]
                if isinstance(shared_secret, int):
                    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
                    encrypted_text_result["shared_secret"] = shared_secret_bytes
                
                self.diffie_hellman_keys = encrypted_text_result
                encrypted_text_for_textbox = encrypted_text.decode("latin1")
                
                self.ui.txtBoxDecrypt.setText(encrypted_text_for_textbox)
                self.ui.txtBoxEncrypt.setText("")
                self.ui.txtBoxKey1.setText("")
                
            elif mapped_algorithm == "RSA":
                encrypted_text_result = algo(text)
                print(f"Encrypted Text: {encrypted_text_result}")
                encrypted_text = encrypted_text_result[0]
                encrypted_text_key = encrypted_text_result[1]
                rsa_cipher_text, rsa_private_key = encrypted_text_result
                self.rsa_encryption_keys = (rsa_cipher_text, rsa_private_key)
                encrypted_text_for_textbox = encrypted_text.decode("latin1")
                self.ui.txtBoxDecrypt.setText(encrypted_text_for_textbox)
                self.ui.txtBoxEncrypt.setText("")
                self.ui.txtBoxKey1.setText("")
            
            elif mapped_algorithm == "DSA":
                encrypted_text_result = algo(text)
                print(f"Encrypted Text: {encrypted_text_result}")
                encrypted_text = encrypted_text_result[0]
                encrypted_text_key = encrypted_text_result[1]
                self.encryption_keys[mapped_algorithm] = encrypted_text_result
                encrypted_text_for_textbox = encrypted_text.decode("latin1")
                self.ui.txtBoxDecrypt.setText(encrypted_text_for_textbox)
                self.ui.txtBoxEncrypt.setText("")
                self.ui.txtBoxKey1.setText("")                
        except Exception as e:
            QMessageBox.warning(self, "Encryption Error", f"An error occurred: {e}")
        
    def btn_decrypt(self):
        """Decryption işlemini gerçekleştirir."""
        # Şifre çözme için kullanıcıdan gelen metni al
        text = self.ui.txtBoxDecrypt.toPlainText()
        if not text:
            QMessageBox.warning(self, "Input Error", "No encrypted text to decrypt!")
            return
        
        encoded_text = text.encode("latin1")  # Latin1 formatına dönüştür

        rsa_informations = self.rsa_encryption_keys
        dsa_informations = self.encryption_keys.get("DSA")
        diffie_hellman_informations = self.diffie_hellman_keys

        # Algoritma seçimini al
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm for Decryption: {selected_algorithm}")

        # Algoritma isimlerini eşleştir
        map_selected_algorithm = {
            "RSA (Rivest–Shamir–Adleman)": "RSA",
            "DSA (Digital Signature Algorithm)": "DSA",
            "Diffie-Hellman Key Exchange": "Diffie-Hellman",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm)
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return

        asymmetric_decryption_algorithms = AsymmetricDecryptionAlgorithms()

        try:
            if mapped_algorithm == "Diffie-Hellman":
                # Gerekli Diffie-Hellman bilgilerini kontrol et
                if not diffie_hellman_informations:
                    QMessageBox.warning(self, "Key Error", "No Diffie-Hellman parameters found!")
                    return
                
                decrypted_text = asymmetric_decryption_algorithms.Diffie_H_decryption(
                    encrypted_message=diffie_hellman_informations["encrypted_message"],
                    nonce=diffie_hellman_informations["nonce"],
                    tag=diffie_hellman_informations["tag"],
                    shared_secret=int.from_bytes(diffie_hellman_informations["shared_secret"], "big")
                )
                print(f"Decrypted Text: {decrypted_text}")
                self.ui.txtBoxEncrypt.setText(decrypted_text)
                self.ui.txtBoxDecrypt.setText("")
            
            elif mapped_algorithm == "RSA":
                # RSA çözümleme
                if not rsa_informations:
                    QMessageBox.warning(self, "Key Error", "No RSA keys found!")
                    return
                
                rsa_cipher_text, rsa_private_key = rsa_informations
                print(f"RSA Cipher Text: {rsa_cipher_text}")
                print(f"RSA Private Key: {rsa_private_key}")
                decrypted_text = asymmetric_decryption_algorithms.rsa_decrypt(
                    rsa_cipher_text,
                    rsa_private_key,
                )
                print(f"Decrypted Text: {decrypted_text}")
                self.ui.txtBoxEncrypt.setText(decrypted_text)
                self.ui.txtBoxDecrypt.setText("")
            
            elif mapped_algorithm == "DSA":
                # DSA doğrulama işlemi
                if not dsa_informations:
                    QMessageBox.warning(self, "Key Error", "No DSA keys found!")
                    return
                
                # DSA çözümleme değil, doğrulama yapar
                is_valid = asymmetric_decryption_algorithms.dsa_verify(
                    text, self.encryption_keys["DSA"][0], self.encryption_keys["DSA"][1]
                )
                result_message = "Signature is VALID!" if is_valid else "Signature is INVALID!"
                self.ui.txtBoxEncrypt.setText(result_message)
                self.ui.txtBoxDecrypt.setText("")
            
        except Exception as e:
            import traceback
            print(traceback.format_exc())  # Hata detaylarını konsola yazdır
            QMessageBox.warning(self, "Decryption Error", f"An error occurred: {e}")   
            
    
    

    




if __name__ == "__main__":
    # PyQt5 uygulamasını başlat
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()  # Ana pencereyi ekranda göster
    sys.exit(app.exec_())  # Uygulamanın düzgün şekilde kapanmasını sağlar
