from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QGraphicsScene
from PyQt5.QtGui import QPixmap

from matplotlib import pyplot as plt
import os
from Crypto.Cipher import DES3

from Forms.SymmetricVsAsymmetricAlgorithms import Ui_Symmetric_Asymmetric_MainWindow
from CompareAlgorithms.CompareSymmetricAsymmetricAlgorihms import SymmetricAsymmetricComparator
from SymmetricAlgorithms.SymmetricEncryptionAlgorithms import SymmetricEncryptionAlgorithms
from AsymmetricAlgorithms.AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()


class SymmetricvsAsymmetric(QtWidgets.QMainWindow):
    def __init__(self,parent=None):
        super(SymmetricvsAsymmetric, self).__init__()
        self.ui = Ui_Symmetric_Asymmetric_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
        self.ui.btnCompare.clicked.connect(self.compare_algorithms)
    
    def close(self,event):
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

        # Seçilebilir algoritmaların eşlenmesi
        map_selected_symmetric_algorithm = {
            "AES": "AES",
            "DES": "DES",
            "3DES": "3DES",
            "Blowfish": "Blowfish",
            "RC4": "RC4",
            "ChaCha20": "ChaCha20",
            "Twofish": "Twofish",
        }

        map_selected_asymmetric_algorithm = {
            "RSA": "RSA",
            "DSA": "DSA",
            "Diffie Hellman Key Exchange": "Diffie-Hellman",
        }

        # Seçilen algoritmaları al
        selected_symmetric_algorithm = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm1)
        selected_asymmetric_algorithm = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm2)

        print(f"Selected Symmetric Algorithm: {selected_symmetric_algorithm}")
        print(f"Selected Asymmetric Algorithm: {selected_asymmetric_algorithm}")

        # Seçilen algoritmaları eşle
        mapped_symmetric_algorithm = map_selected_symmetric_algorithm.get(selected_symmetric_algorithm)
        mapped_asymmetric_algorithm = map_selected_asymmetric_algorithm.get(selected_asymmetric_algorithm)

        if not mapped_symmetric_algorithm or not mapped_asymmetric_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return

        print(f"Mapped Symmetric Algorithm: {mapped_symmetric_algorithm}")
        print(f"Mapped Asymmetric Algorithm: {mapped_asymmetric_algorithm}")
 
        # Anahtarlar
        keys = {
            "AES": os.urandom(16),
            "DES": os.urandom(8),
            "3DES": DES3.adjust_key_parity(os.urandom(24)),
            "RC4": os.urandom(16),
            "Blowfish": os.urandom(16),
            "Twofish": os.urandom(16),
            "ChaCha20": os.urandom(32),
        }

        # Şifreleme algoritmalarının eşlemesi
        symmetric_algorithm_map = {
            "AES": lambda data: SymmetricEncryptionAlgorithms().aes_encrypt(data, key=keys["AES"]),
            "DES": lambda data: SymmetricEncryptionAlgorithms().des_encrypt(data, key=keys["DES"]),
            "3DES": lambda data: SymmetricEncryptionAlgorithms().des3_encrypt(data, key=keys["3DES"]),
            "RC4": lambda data: SymmetricEncryptionAlgorithms().rc4_encrypt(data, key=keys["RC4"]),
            "Blowfish": lambda data: SymmetricEncryptionAlgorithms().blowfish_encrypt(data, key=keys["Blowfish"]),
            "Twofish": lambda data: SymmetricEncryptionAlgorithms().twofish_encrypt(data, key=keys["Twofish"]),
            "ChaCha20": lambda data: SymmetricEncryptionAlgorithms().chacha20_encrypt(data, key=keys["ChaCha20"]),
        }

        asymmetric_algorithm_map = {
            "RSA": lambda data: AsymmetricEncryptionAlgorithms().rsa_encrypt(data),
            "DSA": lambda data: AsymmetricEncryptionAlgorithms().dsa_encrypt(data),
            "Diffie-Hellman": lambda data: AsymmetricEncryptionAlgorithms().diffie_hellman_text_key_exchange(data),
        }

        # Seçilen algoritmalar
        algo1 = symmetric_algorithm_map.get(mapped_symmetric_algorithm)
        algo2 = asymmetric_algorithm_map.get(mapped_asymmetric_algorithm)
        
        
        # Sınıfı oluştur ve algoritmaları karşılaştır
        comparator = SymmetricAsymmetricComparator(algo1, algo2)
        comparison_results = comparator.compare_algorithms(text)
        
        
        # Kategoriler
        categories = ["Performance", "Memory Usage"]
        data1 = [
            comparison_results["algo1_performance"],
            comparison_results["algo1_memory"],
        ]
        data2 = [
            comparison_results["algo2_performance"],
            comparison_results["algo2_memory"],
        ]
        
    
        
        
        # Grafikler
        form_helper.plot_to_graphicsview(
            self.ui.graphPerformance,
            "Performance Comparison",
            [data1[0]],
            [data2[0]],
            ["Performance"]
        )
        
        
        
        form_helper.plot_to_graphicsview(
            self.ui.graphMemoryUsage,
            "Memory Usage",
            [data1[1]],
            [data2[1]],
            ["Memory"]
        )
        
   
    
    


    
    