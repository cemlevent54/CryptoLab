from PyQt5 import QtWidgets,QtCore
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QGraphicsScene
from matplotlib import pyplot as plt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
#RSA
from Crypto.PublicKey import RSA


from Forms.CompositeEncryptionAlgorithms import Ui_Hybrid_Algorithms_MainWindow
from CompareAlgorithms.CompareCompositeAlgorithms import CompositeAlgorithmComparator
from CompositeAlgorithms.CompositeEncryptionAlgorithms import CompositeEncryptionAlgorithms
from CompositeAlgorithms.CompositeDecryptionAlgorithms import CompositeDecryptionAlgorithms

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()



class CompositeEncryption(QtWidgets.QMainWindow):
    encryption_keys = {}
    ecc_aes_encryption_keys = {}
    rsa_aes_encryption_keys = {}
    def __init__(self,parent=None):
        super(CompositeEncryption, self).__init__()
        self.ui = Ui_Hybrid_Algorithms_MainWindow()
        self.ui.setupUi(self)
        self.parent = parent
        
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
            "RSA + AES": "RSA+AES",
            "ECC + AES": "ECC+AES",
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
        composite_encrypt = CompositeEncryptionAlgorithms()
        
        algorithm_map = {
            "RSA+AES": lambda text: composite_encrypt.rsa_aes_encryption(text,composite_encrypt),
            "ECC+AES": lambda text: composite_encrypt.ecc_aes_encryption(text,composite_encrypt),
        }
        
        algo1 = algorithm_map.get(mapped_algorithm_1)
        algo2 = algorithm_map.get(mapped_algorithm_2)
        
        if not algo1 or not algo2:
            QMessageBox.warning(self, "Algorithm Error", "One of the selected algorithms is not supported.")
            return
        
        comparator = CompositeAlgorithmComparator(algo1, algo2)
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

        # Performans grafiği
        form_helper.plot_to_graphicsview(
            self.ui.graphPerformance,
            "Performance Comparison",
            [data1[0]],
            [data2[0]],
            ["Performance"],
        )

        # Güvenlik grafiği
        form_helper.plot_to_graphicsview(
            self.ui.graphSecurity,
            "Security with Frequency Analysis",
            [data1[1]],
            [data2[1]],
            ["Frequency"],
        )

        # Bellek kullanımı grafiği
        form_helper.plot_to_graphicsview(
            self.ui.graphMemoryUsage,
            "Memory Usage",
            [data1[2]],
            [data2[2]],
            ["Memory"],
        )
    
    
    
    def btn_encrypt(self):
        text = self.ui.txtBoxEncrypt.toPlainText()
        
        
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        
        map_selected_algorithm = {
            "RSA + AES": "RSA+AES",
            "ECC + AES": "ECC+AES",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm[0])
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        
        print(f"Selected Algorithms: {selected_algorithm}")
        print(f"Mapped Algorithms: {mapped_algorithm}")
        
        composite_encrypt = CompositeEncryptionAlgorithms()
        
        
        
        # eger mapped_algorithm AES+RSA ise
        if mapped_algorithm == "RSA+AES":
            key_pair = RSA.generate(2048)
            private_key = key_pair.export_key()
            public_key = key_pair.publickey().export_key()
            
            private_key_file = "rsa_aes_private_key.pem"
            public_key_file = "rsa_aes_public_key.pem"
            
            with open(private_key_file,"wb") as priv_file:
                priv_file.write(private_key)
            
            with open(public_key_file,"wb") as pub_file:
                pub_file.write(public_key)
                
            encrypted_data = composite_encrypt.rsa_aes_encrypt(text,public_key.decode())
            print(f"Encrypted Data: {encrypted_data}")
            # print encrypted data to textbox
            self.ui.txtBoxDecrypt.setText(encrypted_data["ciphertext"])
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
            self.rsa_aes_encryption_keys = encrypted_data
            
            
            # mainTester.py da bundan sonra decrypt işlemi başlıyor
        
        elif mapped_algorithm == "ECC+AES":
            composite_encrypt.generate_ecc_keys()
            
            private_key_file = "ecc_aes_private_key.pem"
            public_key_file = "ecc_aes_public_key.pem"
            
            composite_encrypt.save_private_key_to_file(private_key_file)
            composite_encrypt.save_public_key_to_file(public_key_file)
            
            print(f"Private Key: {composite_encrypt.private_key}")
            print(f"Public Key: {composite_encrypt.public_key}")
            
            public_key = composite_encrypt.public_key
            encrypted_data = composite_encrypt.ecc_aes_encrypt(text,public_key)
            print("\nECC + AES Şifrelenmiş veri: ", encrypted_data)
            # print encrypted data to textbox
            self.ui.txtBoxDecrypt.setText(encrypted_data["ciphertext"])
            self.ui.txtBoxEncrypt.setText("")
            self.ui.txtBoxKey1.setText("")
            self.ecc_aes_encryption_keys = encrypted_data
            
            # mainTester.py da bundan sonra decrypt işlemi başlıyor
    
    def btn_decrypt(self):
        text = self.ui.txtBoxDecrypt.toPlainText()
        composite_encrypt = CompositeEncryptionAlgorithms()
        if not text:
            QMessageBox.warning(self, "Input Error", "No encrypted text to decrypt!")
            return
        
        ecc_aes_informations = self.ecc_aes_encryption_keys
        rsa_aes_informations = self.rsa_aes_encryption_keys
        
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm for Decryption: {selected_algorithm}")
        
        map_selected_algorithm = {
            "RSA + AES": "RSA+AES",
            "ECC + AES": "ECC+AES",
        }
        
        mapped_algorithm = map_selected_algorithm.get(selected_algorithm[0])
        if not mapped_algorithm:
            QMessageBox.warning(self, "Mapping Error", "Selected algorithm is not supported!")
            return
        
        composite_decrypt = CompositeDecryptionAlgorithms()
        
        if mapped_algorithm == "RSA+AES":
            if not rsa_aes_informations:
                QMessageBox.warning(self, "Key Error", "No RSA+AES keys found!")
                return
            # private_key i dosyadan yükle
            private_key_file = "rsa_aes_private_key.pem"
            with open(private_key_file,"rb") as priv_file:
                private_key = RSA.import_key(priv_file.read())
            
            decrypted_text = composite_decrypt.rsa_aes_decrypt(rsa_aes_informations,private_key.export_key())
            
            print(f"Decrypted Text: {decrypted_text}")
            self.ui.txtBoxEncrypt.setText(decrypted_text)
            self.ui.txtBoxDecrypt.setText("")
            self.ui.txtBoxKey2.setText("")
        
        elif mapped_algorithm == "ECC+AES":
            if not ecc_aes_informations:
                QMessageBox.warning(self, "Key Error", "No ECC+AES keys found!")
                return
            
            # Anahtarları dosyadan yükle
            private_key_file = "ecc_aes_private_key.pem"
            public_key_file = "ecc_aes_public_key.pem"
            
            composite_encrypt.load_private_key_from_file(private_key_file)
            composite_encrypt.load_public_key_from_file(public_key_file)
            
            private_key = composite_encrypt.private_key
            public_key = composite_encrypt.public_key

            # Decryption işlemi
            decrypted_text = composite_decrypt.ecc_aes_decrypt(
                ecc_aes_informations, private_key, public_key
            )
            print(f"Decrypted Text: {decrypted_text}")
            self.ui.txtBoxEncrypt.setText(decrypted_text)
            self.ui.txtBoxDecrypt.setText("")
            self.ui.txtBoxKey2.setText("")

        
    
    def generate_ecc_keys(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def save_private_key_to_file(self, filename: str):
        """
        Özel anahtarı PEM formatında belirtilen dosyaya kaydeder.
        """
        with open(filename, "wb") as file:
            file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    
    def save_public_key_to_file(self, filename: str):
        """
        Genel anahtarı PEM formatında belirtilen dosyaya kaydeder.
        """
        with open(filename, "wb") as file:
            file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    
    def load_private_key_from_file(self, filename: str):
        """
        Belirtilen dosyadan özel anahtarı yükler.
        """
        with open(filename, "rb") as file:
            self.private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend()
            )
    
    def load_public_key_from_file(self, filename: str):
        """
        Belirtilen dosyadan genel anahtarı yükler.
        """
        with open(filename, "rb") as file:
            self.public_key = serialization.load_pem_public_key(
                file.read(),
                backend=default_backend()
            )