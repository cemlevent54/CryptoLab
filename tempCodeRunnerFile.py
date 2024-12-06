def btn_encrypt(self):
        # Get data from textbox
        text = self.ui.txtBoxEncrypt.toPlainText()

        # Anahtar oluşturma
        keys = {
            "AES": os.urandom(16),  # AES Key (128 bits)
            "DES": os.urandom(8),   # DES Key (64 bits)
            "3DES": DES3.adjust_key_parity(os.urandom(24)),  # 3DES Key (192 bits)
            "RC4": os.urandom(16),  # RC4 Key (128 bits)
            "Blowfish": os.urandom(16),  # Blowfish Key (128 bits)
            "Twofish": os.urandom(16),   # Twofish Key (128 bits)
        }

        # Seçili algoritmayı alın
        selected_algorithm = self.get_selected_algorithm(self.ui.grpBox_Algorithm1)
        if not selected_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select an algorithm!")
            return
        print(f"Selected Algorithm: {selected_algorithm}")
        
        map_selected_algorithm = {
            "AES(Advanced Encryption Standart)": "AES",
            "DES": "DES",
            "3DES": "DES3",
            "RC4": "RC4",
            "Blowfish": "Blowfish",
            "Twofish": "Twofish",
        }
        # Anahtarı sakla
        key = keys[map_selected_algorithm[selected_algorithm]]
        self.encryption_keys[selected_algorithm] = key

        # Algoritma haritasını oluştur
        algorithm_map = {
            "AES": lambda text: SymmetricEncryptionAlgorithms().aes_encrypt(text, key),
            "DES": lambda text: SymmetricEncryptionAlgorithms().des_encrypt(text, key),
            "3DES": lambda text: SymmetricEncryptionAlgorithms().des3_encrypt(text, key),
            "RC4": lambda text: SymmetricEncryptionAlgorithms().rc4_encrypt(text, key),
            "Blowfish": lambda text: SymmetricEncryptionAlgorithms().blowfish_encrypt(text, key),
            "Twofish": lambda text: SymmetricEncryptionAlgorithms().twofish_encrypt(text, key),
        }

        # Seçili algoritmayı çalıştır
        algo = algorithm_map.get(selected_algorithm)
        if not algo:
            QMessageBox.warning(self, "Encryption Error", "Invalid algorithm selected!")
            return

        # Şifreleme işlemi
        encrypted_text = algo(text)

        # Sonuçları arayüze yazdır
        self.ui.txtBoxDecrypt.setText(encrypted_text)
        self.ui.txtBoxEncrypt.setText("")
        self.ui.txtBoxKey1.setText("")