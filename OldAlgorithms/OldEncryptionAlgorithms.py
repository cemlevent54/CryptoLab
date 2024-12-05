import string
from itertools import cycle


class OldEncryptionAlgorithms:
    def __init__(self):
        self.alphabet = string.ascii_uppercase

    def caesar_cipher(self, text, shift):
        return self._caesar(text, shift)

    def vigenere_cipher(self, text, key):
        return self._vigenere(text, key)

    def substitution_cipher(self, text, key):
        return self._substitution(text, key)

    def transposition_cipher(self, text, key):
        return self._transposition(text, key)

    def playfair_cipher(self, text, key):
        return self._playfair(text, key, encrypt=True)

    def enigma_machine(self, text, key):
        return self._enigma(text, key, encrypt=True)

    def _caesar(self, text, shift, encrypt=True):
        shift = shift if encrypt else -shift
        result = ""
        for char in text.upper():
            if char in self.alphabet:
                new_index = (self.alphabet.index(char) + shift) % 26
                result += self.alphabet[new_index]
            else:
                result += char
        return result

    def _vigenere(self, text, key, encrypt=True):
        key = key.upper()
        key_cycle = cycle(key)
        result = ""
        for char in text.upper():
            if char in self.alphabet:
                shift = self.alphabet.index(next(key_cycle))
                shift = shift if encrypt else -shift
                new_index = (self.alphabet.index(char) + shift) % 26
                result += self.alphabet[new_index]
            else:
                result += char
        return result

    def _substitution(self, text, key, encrypt=True):
        key_map = dict(zip(self.alphabet, key.upper())) if encrypt else dict(zip(key.upper(), self.alphabet))
        result = "".join([key_map.get(char, char) for char in text.upper()])
        return result

    def _transposition(self, text, key, encrypt=True):
        if encrypt:
            result = [''] * key
            for index, char in enumerate(text):
                result[index % key] += char
            return ''.join(result)
        else:
            num_columns = (len(text) + key - 1) // key
            num_rows = key
            num_shaded_boxes = (num_columns * num_rows) - len(text)
            plaintext = [''] * num_columns
            col, row = 0, 0
            for char in text:
                plaintext[col] += char
                col += 1
                if (col == num_columns) or (col == num_columns - 1 and row >= num_rows - num_shaded_boxes):
                    col, row = 0, row + 1
            return ''.join(plaintext)

    def _playfair(self, text, key, encrypt=True):
        def create_matrix(key):
            matrix = []
            used_letters = set()
            key = key.upper().replace('J', 'I')
            for char in key + self.alphabet:
                if char not in used_letters and char != 'J':
                    matrix.append(char)
                    used_letters.add(char)
            return [matrix[i:i + 5] for i in range(0, len(matrix), 5)]

        def find_position(matrix, char):
            for row_idx, row in enumerate(matrix):
                if char in row:
                    return row_idx, row.index(char)

        key_matrix = create_matrix(key)
        text = text.upper().replace('J', 'I')  # Replace 'J' with 'I' to simplify matrix
        text = text.replace(" ", "")  # Remove spaces
        text = text if len(text) % 2 == 0 else text + 'X'  # Ensure even length

        pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
        result = []

        for a, b in pairs:
            row_a, col_a = find_position(key_matrix, a)
            row_b, col_b = find_position(key_matrix, b)
            if row_a == row_b:  # Same row
                result.append(key_matrix[row_a][(col_a + (1 if encrypt else -1)) % 5])
                result.append(key_matrix[row_b][(col_b + (1 if encrypt else -1)) % 5])
            elif col_a == col_b:  # Same column
                result.append(key_matrix[(row_a + (1 if encrypt else -1)) % 5][col_a])
                result.append(key_matrix[(row_b + (1 if encrypt else -1)) % 5][col_b])
            else:  # Rectangle
                result.append(key_matrix[row_a][col_b])
                result.append(key_matrix[row_b][col_a])
        return ''.join(result)


    def _enigma(self, text, key, encrypt=True):
        rotor = key.upper()
        result = ""
        for char in text.upper():
            if char in self.alphabet:
                index = (self.alphabet.index(char) + (self.alphabet.index(rotor[0]) if encrypt else -self.alphabet.index(rotor[0]))) % 26
                result += self.alphabet[index]
                rotor = rotor[1:] + rotor[0]
            else:
                result += char
        return result


class DecryptionAlgorithms(OldEncryptionAlgorithms):
    def caesar_cipher(self, text, shift):
        return self._caesar(text, shift, encrypt=False)

    def vigenere_cipher(self, text, key):
        return self._vigenere(text, key, encrypt=False)

    def substitution_cipher(self, text, key):
        return self._substitution(text, key, encrypt=False)

    def transposition_cipher(self, text, key):
        return self._transposition(text, key, encrypt=False)

    def playfair_cipher(self, text, key):
        return self._playfair(text, key, encrypt=False)

    def enigma_machine(self, text, key):
        return self._enigma(text, key, encrypt=False)
