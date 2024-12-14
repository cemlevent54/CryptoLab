from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib import pyplot as plt

from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from AsymmetricAlgorithms.AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms
from AsymmetricAlgorithms.AsymmetricDecryptionAlgorithms import AsymmetricDecryptionAlgorithms

from CompareAlgorithms.CompareAsymmetricAlgorithms import AsymmetricAlgorithmComparator

from Forms.AsymmetricEncryptionAlgorithms import Ui_Asymmetic_Encryption_MainWindow

from Helpers.FormHelper import FormHelper

form_helper = FormHelper()

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
        
        form_helper.plot_to_graphicsview(self.ui.graphPerformance, "Performance Comparison", [data1[0]], [data2[0]], ["Performance"])
        form_helper.plot_to_graphicsview(self.ui.graphSecurity, "Security with Frequency Analysis", [data1[1]], [data2[1]], ["Frequency"])
        form_helper.plot_to_graphicsview(self.ui.graphMemoryUsage, "Memory Usage", [data1[2]], [data2[2]], ["Memory"])        
    
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
   