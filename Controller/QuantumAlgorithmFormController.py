from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib import pyplot as plt
from PyQt5 import QtCore

from Forms.QuantumEncryptionAlgorithms import Ui_Quantum_Encryption_MainWindow
from QuantumAlgorithms.QuantumEncryptionAlgorithms import QuantumEncryptionAlgorithms
from QuantumAlgorithms.QuantumDecryptionAlgorithms import QuantumDecryptionAlgorithms
from CompareAlgorithms.CompareQuantumAlgorithms import QuantumAlgorithmComparator

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()

class QuantumEncryption(QtWidgets.QMainWindow):
    keys = {}
    def __init__(self,parent=None):
        super(QuantumEncryption,self).__init__()
        self.ui = Ui_Quantum_Encryption_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
        # Algoritma karşılaştırma butonuna olay bağlama
        self.ui.btnEncrypt.clicked.connect(self.btn_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.btn_decrypt)
        self.ui.btnCompare.clicked.connect(self.compare_algorithms)
    
    def closeEvent(self, event):
        if self.parent:
            self.parent.show()
        event.accept()
        
    def get_selected_algorithm(self,groupbox):
        """Seçili algoritmaları bulur"""
        for radio_button in groupbox.findChildren(QtWidgets.QRadioButton):
            if radio_button.isChecked():
                return [radio_button.text()]
        return None
     
    def get_selected_algorithm_not_list(self,groupbox):
        """Seçili algoritmaları bulur"""
        for radio_button in groupbox.findChildren(QtWidgets.QRadioButton):
            if radio_button.isChecked():
                return radio_button.text()
        return None

    def btn_encrypt(self):
        text = self.ui.txtBoxEncrypt.toPlainText()
        
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        
        map_selected_algorithm = {
            "Lattice Based Cryptography": "Lattice Based Cryptography",
            "Code Based Cryptography": "Code Based Cryptography",
            "Hash Based Cryptography": "Hash Based Cryptography",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm[0])
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        
        print(f"Selected Algorithm: {selected_algorithm}")
        print(f"Mapped Algorithm: {mapped_algorithm}")
        
        quantum_encrypt = QuantumEncryptionAlgorithms()
        
        if mapped_algorithm == "Lattice Based Cryptography":
            public_key = quantum_encrypt.PUBLIC_KEY
            self.keys["Lattice Based Cryptography"] = public_key
            print(f"Public Key: {public_key}")
            encrypted_text = quantum_encrypt.lattice_encrypt(text, public_key)
            print(f"Encrypted Text: {encrypted_text}")
            
            self.ui.txtBoxDecrypt.setText(encrypted_text)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
            
            
        elif mapped_algorithm == "Code Based Cryptography":
            key = 42
            self.keys["Code Based Cryptography"] = key
            encrypted_text = quantum_encrypt.code_based_encrypt(text, key)
            print(f"Encrypted Text: {encrypted_text}")
            
            self.ui.txtBoxDecrypt.setText(encrypted_text)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
            
            
        elif mapped_algorithm == "Hash Based Cryptography":
            hashed_message = quantum_encrypt.hash_encrypt(text)
            print(f"Hashed Message: {hashed_message}")
            self.ui.txtBoxDecrypt.setText(hashed_message)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
    
    def btn_decrypt(self):
        text = self.ui.txtBoxDecrypt.toPlainText()
        
        if not text:
            QMessageBox.warning(self, "Input Error", "No encrypted text to decrypt!")
            return
        
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm for Decryption: {selected_algorithm}")
        
        map_selected_algorithm = {
            "Lattice Based Cryptography": "Lattice Based Cryptography",
            "Code Based Cryptography": "Code Based Cryptography",
            "Hash Based Cryptography": "Hash Based Cryptography",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm[0])
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        
        quantum_decrypt = QuantumDecryptionAlgorithms()
        
        if mapped_algorithm == "Lattice Based Cryptography":
           public_key = self.keys.get("Lattice Based Cryptography")
           if not public_key:
               QMessageBox.warning(self, "Key Error", "No public key found for Lattice Based Cryptography!")
               return
           
           decrypted_text = quantum_decrypt.lattice_decrypt(text, public_key)
           print(f"Decrypted Text: {decrypted_text}")
           
           self.ui.txtBoxEncrypt.setText(decrypted_text)
           self.ui.txtBoxDecrypt.setText("")
           self.ui.txtBoxKey2.setText("")
        elif mapped_algorithm == "Code Based Cryptography":
            key = self.keys.get("Code Based Cryptography")
            if not key:
                QMessageBox.warning(self, "Key Error", "No key found for Code Based Cryptography!")
                return
            decrypted_text = quantum_decrypt.code_based_decrypt(text, key)
            print(f"Decrypted Text: {decrypted_text}")
            self.ui.txtBoxEncrypt.setText(decrypted_text)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey2.setText("")
            
        elif mapped_algorithm == "Hash Based Cryptography":
            hashed_message = "Hashing is irreversible!"
            self.ui.txtBoxEncrypt.setText(hashed_message)
            self.ui.txtBoxDecrypt.setText("")
            self.ui.txtBoxKey2.setText("")
    
    def compare_algorithms(self):
        map_selected_algorithm = {
            "Lattice Based Cryptography": "Lattice Based Cryptography",
            "Code Based Cryptography": "Code Based Cryptography",
            "Hash Based Cryptography": "Hash Based Cryptography",
        }
        
        selected_algorithm_1 = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm1)
        selected_algorithm_2 = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm2)
        print(f"Selected Algorithms: {selected_algorithm_1} vs {selected_algorithm_2}")
        
        mapped_algorithm_1 = map_selected_algorithm.get(selected_algorithm_1) 
        mapped_algorithm_2 = map_selected_algorithm.get(selected_algorithm_2)
        print(f"Mapped Algorithms: {mapped_algorithm_1} vs {mapped_algorithm_2}")
        
        if not mapped_algorithm_1 or not mapped_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return
        
        quantum_encrypt = QuantumEncryptionAlgorithms()
        
        algorithm_map = {
            "Lattice Based Cryptography": lambda text: quantum_encrypt.lattice_encrypt(text, quantum_encrypt.PUBLIC_KEY),
            "Code Based Cryptography": lambda text: quantum_encrypt.code_based_encrypt(text, 42),
            "Hash Based Cryptography": lambda text: quantum_encrypt.hash_encrypt(text),
        }
        
        algo1 = algorithm_map.get(mapped_algorithm_1)
        algo2 = algorithm_map.get(mapped_algorithm_2)
        
        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return
        
        # comparator
        comparator = QuantumAlgorithmComparator(algo1, algo2)
        test_data = "exampledatafortestingalgorithms"
        key_space = 2 ** 16
        comparison_results = comparator.compare_algorithms(test_data, key_space)
        
        categories = ["Performance", "Security", "Memory Usage"]
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
        
        form_helper.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])
        form_helper.plot_to_graphicsview(self.ui.graphSecurity, "Security with Frequency Analysis", [data1[1]], [data2[1]], ["Security"])
        form_helper.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])
        
    
    