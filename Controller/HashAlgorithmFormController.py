from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib import pyplot as plt

from Forms.HashingAlgorithms import Ui_Hashing_Algorithms_MainWindow
from HashingAlgorithms.HashingAlgorithms import HashingAlgorithmsEncrypt
from CompareAlgorithms.CompareHashAlgorithms import HashingAlgorithmsComparator

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()


class HashAlgorithms(QtWidgets.QMainWindow):
    original_text = ""
    def __init__(self,parent=None):
        super(HashAlgorithms,self).__init__()
        self.ui = Ui_Hashing_Algorithms_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
        self.ui.btnEncrypt.clicked.connect(self.btn_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.btn_decrypt)
        self.ui.btnCompare.clicked.connect(self.compare_algorithms)
        
    def closeEvent(self, event):
        # Pencere kapanırken ana pencereyi yeniden göster
        if self.parent:
            self.parent.show()
        event.accept()
        
    def get_selected_algorithm(self, groupbox):
        """Seçili algoritmaları bulur."""
        for child in groupbox.findChildren(QtWidgets.QRadioButton):
            if child.isChecked():
                return child.text()
        return None
    
    
    def btn_encrypt(self):
        text = self.ui.txtBoxEncrypt.toPlainText()
        if not text:
            QMessageBox.warning(self, "Input Error", "Please enter text to hash!")
            return

        # Seçili algoritmayı al
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        
        hash_algorithm = HashingAlgorithmsEncrypt()
        print(f"Selected Algorithm: {selected_algorithm}")

        # UI ile uyumlu algoritma isimleri haritası
        hash_functions = {
            "MD5": hash_algorithm.md5,
            "SHA 1": hash_algorithm.sha1,         
            "SHA 256": hash_algorithm.sha256,      
            "SHA 512": hash_algorithm.sha512,      
            "Blake2b": hash_algorithm.blake2b,
            "Blake2s": hash_algorithm.blake2s,
            "Argon2": hash_algorithm.argon2,
            "CRC32": hash_algorithm.crc32
        }

        # Hash algoritmasını seç ve çalıştır
        hash_algorithm = HashingAlgorithmsEncrypt()
        if selected_algorithm in hash_functions:
            hashed_text = hash_functions[selected_algorithm](text)
            print(f"{selected_algorithm} Hash: {hashed_text}")
            self.original_text = hashed_text
            self.ui.txtBoxDecrypt.setText(hashed_text)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
        else:
            QMessageBox.warning(self, "Unsupported Algorithm", "The selected algorithm is not supported!")
    
    def btn_decrypt(self):
        self.ui.txtBoxEncrypt.setText("Hashing is irreversible!")
        self.ui.txtBoxDecrypt.setText("")
        self.ui.txtBoxKey2.setText("")
        
    def compare_algorithms(self):
        map_selected_algorithm = {
            "MD5": "MD5",
            "SHA 1": "SHA 1",
            "SHA 256": "SHA 256",
            "SHA 512": "SHA 512",
            "Blake2b": "Blake2b",
            "Blake2s": "Blake2s",
            "Argon2": "Argon2",
            "CRC32": "CRC32"
        }
        
        selected_algorithm_1 = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        selected_algorithm_2 = self.get_selected_algorithm(self.ui.grpBox_Algorithm2)
        print(f"Selected Algorithms: {selected_algorithm_1} vs {selected_algorithm_2}")
        
        mapped_algorithm_1 = map_selected_algorithm.get(selected_algorithm_1)  
        mapped_algorithm_2 = map_selected_algorithm.get(selected_algorithm_2)
        print(f"Mapped Algorithms: {mapped_algorithm_1} vs {mapped_algorithm_2}")
        
        if not mapped_algorithm_1 or not mapped_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return
        
        hash_algorithm = HashingAlgorithmsEncrypt()
        
        algorithm_map = {
            "MD5": lambda text : hash_algorithm.md5(text),
            "SHA 1": lambda text : hash_algorithm.sha1(text),
            "SHA 256": lambda text : hash_algorithm.sha256(text),
            "SHA 512": lambda text : hash_algorithm.sha512(text),
            "Blake2b": lambda text : hash_algorithm.blake2b(text),
            "Blake2s": lambda text : hash_algorithm.blake2s(text),
            "Argon2": lambda text : hash_algorithm.argon2(text),
            "CRC32": lambda text : hash_algorithm.crc32(text),
        }
        
        algo1 = algorithm_map.get(mapped_algorithm_1)
        algo2 = algorithm_map.get(mapped_algorithm_2)
        
        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return
        
        comparator = HashingAlgorithmsComparator(algo1, algo2)
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
        
        # graphs
        
        form_helper.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])
        form_helper.plot_to_graphicsview(self.ui.graphSecurity, "Security Comparison", [data1[1]], [data2[1]], ["Security"])
        form_helper.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])
        
    
    