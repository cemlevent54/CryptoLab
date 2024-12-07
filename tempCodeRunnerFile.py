algorithm_map = {
            "RSA": lambda text: AsymmetricEncryptionAlgorithms().rsa_encrypt(text),
            "DSA": lambda text: AsymmetricEncryptionAlgorithms().dsa_encrypt(text),
            "Diffie-Hellman": lambda text: AsymmetricEncryptionAlgorithms().diffie_hellman_text_key_exchange(text),
        }