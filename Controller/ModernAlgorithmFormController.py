from PyQt5 import QtWidgets,QtCore
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPixmap
from matplotlib import pyplot as plt
from PyQt5.QtWidgets import QGraphicsScene

from Forms.modernEncryptionAlgorithms import Ui_Modern_Encryption_MainWindow
from ModernAlgorithms.ModernEncryptionAlgorithms import AESGCMEncryption, RSAPSS
from ModernAlgorithms.ModernDecryptionAlgorithms import AESGCMDecryption

from CompareAlgorithms.CompareModernAlgorithms import ModernAlgorithmComparator

from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from Crypto.PublicKey import RSA

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()

class ModernEncryption(QtWidgets.QMainWindow):
    aes_gcm_key = ""
    rsa_pss_key = ""
    aes_gcm_encryption_data = {}
    rsa_pss_encryption_data = {}
    rsa_pss_public_key = ""
    rsa_pss_private_key = ""
    rsa_pss_signature = ""
    rsa_pss_original_message = ""
    def __init__(self,parent=None):
        super(ModernEncryption,self).__init__()
        self.ui = Ui_Modern_Encryption_MainWindow()
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
        map_selected_algorithm = {
            "AES-GCM(Advanced Encryption Standard - Galois/Counter Mode)": "AES-GCM",
            "RSA-PSS (Probabilistic Signature Scheme)": "RSA-PSS",
        }
        
        selected_algorithm_1 = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm1)
        selected_algorithm_2 = self.get_selected_algorithm_not_list(self.ui.grpBox_Algorithm2)
        
        if not selected_algorithm_1 or not selected_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return
        
        mapped_algorithm_1 = map_selected_algorithm.get(selected_algorithm_1)
        mapped_algorithm_2 = map_selected_algorithm.get(selected_algorithm_2)
        
        print(f"Selected Algorithms: {selected_algorithm_1} vs {selected_algorithm_2}")
        print(f"Mapped Algorithms: {mapped_algorithm_1} vs {mapped_algorithm_2}")
        
        if not mapped_algorithm_1 or not mapped_algorithm_2:
            QMessageBox.warning(self, "Selection Error", "One of the selected algorithms is not supported.")
            return
        
        
        
        
        aes_key = AESGCMEncryption.generate_aes_key()
        print(f"Generated AES Key: {aes_key}")
        rsa_key_pair = RSA.generate(2048)
        private_key = rsa_key_pair.export_key()
        public_key = rsa_key_pair.publickey().export_key()
        print(f"Generated RSA Private Key: {private_key}")
        print(f"Generated RSA Public Key: {public_key}")
        algorithm_map = {
            "AES-GCM" : lambda text : AESGCMEncryption().aes_gcm_encrypt(text,aes_key),
            "RSA-PSS" : lambda text : RSAPSS().rsa_pss_sign(text,private_key),
        }
        
        algo1 = algorithm_map.get(mapped_algorithm_1)
        algo2 = algorithm_map.get(mapped_algorithm_2)
        
        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return
        
        #comparators
        comparator = ModernAlgorithmComparator(algo1,algo2)
        test_data = "exampledatafortestingalgorithms"
        key_space = 2 ** 16
        comparison_results = comparator.compare_algorithms(test_data,key_space)
        
        categories = ["Performance", "Size", "Memory Usage"]
        data1 = [
            comparison_results["algo1_performance"],
            comparison_results["algo1_size"],
            comparison_results["algo1_memory"],
        ]
        data2 = [
            comparison_results["algo2_performance"],
            comparison_results["algo2_size"],
            comparison_results["algo2_memory"],
        ]
        
        # plot to graphics view
        form_helper.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])
        form_helper.plot_to_graphicsview(self.ui.graphSecurity, "Size of outputs", [data1[1]], [data2[1]], ["Size"])
        form_helper.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])
                                                                                                             
    def btn_encrypt(self):
        """Şifreleme işlemini gerçekleştirir"""
        
        text = self.ui.txtBoxEncrypt.toPlainText()
        
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        
        map_selected_algorithm = {
            "AES-GCM(Advanced Encryption Standard - Galois/Counter Mode)": "AES-GCM",
            "RSA-PSS (Probabilistic Signature Scheme)": "RSA-PSS",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm[0])
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        
        print(f"Selected Algorithm: {selected_algorithm}")
        print(f"Mapped Algorithm: {mapped_algorithm}")
        
        if mapped_algorithm == "AES-GCM":
            aes_key = AESGCMEncryption.generate_aes_key()
            print(f"AES Key: {aes_key}")
            self.aes_gcm_key = aes_key
            encrypted_data = AESGCMEncryption().aes_gcm_encrypt(text,aes_key)
            print(f"Encrypted Data: {encrypted_data}")
            self.aes_gcm_encryption_data = encrypted_data
            encrypted_text = encrypted_data["ciphertext"]
            print(f"Encrypted Text: {encrypted_text}")
            self.ui.txtBoxDecrypt.setText(encrypted_text)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
            
        elif mapped_algorithm == "RSA-PSS":
            text = text.strip()
            self.rsa_pss_original_message = text
            rsa_private_key, rsa_public_key = RSAPSS.generate_rsa_key_pair()
            print(f"RSA Private Key: {rsa_private_key}")
            print(f"RSA Public Key: {rsa_public_key}")
            self.rsa_pss_private_key = rsa_private_key
            self.rsa_pss_public_key = rsa_public_key
            signature = RSAPSS().rsa_pss_sign(text,rsa_private_key)
            print(f"Signature: {signature}")
            self.rsa_pss_signature = signature
            self.ui.txtBoxDecrypt.setText(signature)
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
    
    def btn_decrypt(self):
        """Deşifreleme işlemini gerçekleştirir"""
        text = self.ui.txtBoxDecrypt.toPlainText()
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        
        map_selected_algorithm = {
            "AES-GCM(Advanced Encryption Standard - Galois/Counter Mode)": "AES-GCM",
            "RSA-PSS (Probabilistic Signature Scheme)": "RSA-PSS",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm[0])
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        
        print(f"Selected Algorithm: {selected_algorithm}")
        print(f"Mapped Algorithm: {mapped_algorithm}")
        
        if mapped_algorithm == "AES-GCM":
            aes_key = self.aes_gcm_key
            aes_gcm_encrypted_data = self.aes_gcm_encryption_data
            
            decrypted_text = AESGCMDecryption().aes_gcm_decrypt(aes_gcm_encrypted_data, aes_key)
            print(f"Decrypted Text: {decrypted_text}")
            self.ui.txtBoxEncrypt.setText(decrypted_text)
            self.ui.txtBoxDecrypt.setText("")
            self.ui.txtBoxKey2.setText("")
            
        elif mapped_algorithm == "RSA-PSS":
            try:
                # Public Key ve Signature kontrolü
                if not self.rsa_pss_public_key or not self.rsa_pss_signature:
                    QMessageBox.warning(self, "RSA-PSS Error", "No RSA-PSS signature or public key found!")
                    return

                # Orijinal mesajı kullan
                original_message = self.rsa_pss_original_message
                rsa_public_key = self.rsa_pss_public_key
                rsa_pss_signature = self.rsa_pss_signature

                # Debug için verileri ekrana yazdır
                print("Doğrulama için kullanılan veriler:")
                print(f"Original Message: '{original_message}'")
                print(f"Public Key:\n{rsa_public_key.decode()}")
                print(f"Signature (Base64): {rsa_pss_signature}")

                # İmzayı doğrula
                is_valid = RSAPSS.rsa_pss_verify(original_message, rsa_pss_signature, rsa_public_key)

                # Doğrulama sonucunu ekrana yaz
                result_message = "Signature is VALID!" if is_valid else "Signature is INVALID!"
                print(result_message)
                self.ui.txtBoxEncrypt.setText(result_message)

                # UI temizleme
                self.ui.txtBoxDecrypt.clear()
                self.ui.txtBoxKey2.clear()

            except Exception as e:
                print(f"Doğrulama Hatası: {e}")
                QMessageBox.warning(self, "Verification Error", f"Failed to verify RSA-PSS signature: {e}")
    
    