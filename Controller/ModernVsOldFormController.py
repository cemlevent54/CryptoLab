from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib import pyplot as plt
from PyQt5.QtWidgets import QMessageBox

from Forms.ModernVsOldAlgorithms import Ui_Modern_Old_MainWindow
from ModernAlgorithms.ModernEncryptionAlgorithms import AESGCMEncryption, RSAPSS
from OldAlgorithms.OldEncryptionAlgorithms import OldEncryptionAlgorithms, DecryptionAlgorithms
from CompareAlgorithms.CompareModernOldAlgorithm import ModernOldComparator

import os
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA     

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()
    
class ModernvsOld(QtWidgets.QMainWindow):
    def __init__(self,parent=None):
        super(ModernvsOld,self).__init__()
        self.ui = Ui_Modern_Old_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
        # buton olayları
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
    
    def compare_algorithms(self):
        text = "exampledatafortestingalgorithms"
        key_space = 2 ** 16
        
        map_selected_modern_algorithm = {
            "AES - GCM": "AES-GCM",
            "RSA - PSS": "RSA-PSS",
        }
        
        map_selected_old_algorithm = {
            "Caesar Cipher": "Caesar Cipher",
            "Vigenere Cipher": "Vigenere Cipher",
            "Transposition Cipher": "Transposition Cipher",
            "Substitution Cipher": "Substitution Cipher",
            "Playfair Cipher": "Playfair Cipher",
            "Enigma Machine": "Enigma Machine",
        }
        
        selected_modern_algorithm = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm1)
        selected_old_algorithm = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm2)
        
        print(f"Selected Modern Algorithm: {selected_modern_algorithm}")
        print(f"Selected Old Algorithm: {selected_old_algorithm}")
        
        mapped_modern_algorithm = map_selected_modern_algorithm.get(selected_modern_algorithm)
        mapped_old_algorithm = map_selected_old_algorithm.get(selected_old_algorithm)
        
        if not mapped_modern_algorithm or not mapped_old_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return
        
        print(f"Mapped Modern Algorithm: {mapped_modern_algorithm}")
        print(f"Mapped Old Algorithm: {mapped_old_algorithm}")
        
        aes_key_for_modern_algorithm = AESGCMEncryption.generate_aes_key()
        print(f"AES Key for Modern Algorithm: {aes_key_for_modern_algorithm}")
        rsa_key_pair_for_modern_algorithm = RSA.generate(2048)
        private_key_for_modern_algorithm = rsa_key_pair_for_modern_algorithm.export_key()
        public_key_for_modern_algorithm = rsa_key_pair_for_modern_algorithm.publickey().export_key()
        print(f"RSA Private Key for Modern Algorithm: {private_key_for_modern_algorithm}")
        print(f"RSA Public Key for Modern Algorithm: {public_key_for_modern_algorithm}")
        
        modern_algorithm_map = {
            "AES-GCM": lambda data: AESGCMEncryption().aes_gcm_encrypt(data, aes_key_for_modern_algorithm),
            "RSA-PSS": lambda data: RSAPSS().rsa_pss_sign(data, private_key_for_modern_algorithm),
        }
        
        old_algorithm_map = {
            "Caesar Cipher": lambda text: OldEncryptionAlgorithms().caesar_cipher(text, shift=3),
            "Vigenere Cipher": lambda text: OldEncryptionAlgorithms().vigenere_cipher(text, key="AYUSH"),
            "Substitution Cipher": lambda text: OldEncryptionAlgorithms().substitution_cipher(text, key="QWERTYUIOPASDFGHJKLZXCVBNM"),
            "Transposition Cipher": lambda text: OldEncryptionAlgorithms().transposition_cipher(text, key=5),
            "Playfair Cipher": lambda text: OldEncryptionAlgorithms().playfair_cipher(text, key="KEYWORD"),
            "Enigma Machine": lambda text: OldEncryptionAlgorithms().enigma_machine(text, key="ROTOR"),
        }
        
        algo1 = modern_algorithm_map.get(mapped_modern_algorithm)
        algo2 = old_algorithm_map.get(mapped_old_algorithm)
        
        comparator = ModernOldComparator(algo1, algo2)
        comparison_results = comparator.compare_algorithms(text)
        
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
        form_helper.plot_to_graphicsview(self.ui.graphSecurity, "Security Comparison", [data1[1]], [data2[1]], ["Security"])
        form_helper.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])
        
        
    
    