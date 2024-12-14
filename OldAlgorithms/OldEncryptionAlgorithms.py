import string
from itertools import cycle

class OldEncryptionAlgorithms:
    def __init__(self):
        self.alphabet = string.ascii_uppercase

    def caesar_cipher(self, text, shift):
        return self._caesar(text, shift)

    def vigenere_cipher(self, text, key):
        return self._vigenere(text, key, encrypt=True)

    def substitution_cipher(self, text, key):
        return self._substitution(text, key)

    def transposition_cipher(self, text, key):
        return self._transposition(text, key)

    def playfair_cipher(self, text, key):
        return self._playfair(text, key, encrypt=True)

    def enigma_machine(self, text, key):
        return self._enigma(text, key, encrypt=True)

    # YARDIMCI METODLAR
    def _caesar(self, text, shift, encrypt=True):
        shift = shift if encrypt else -shift
        return ''.join(
            self.alphabet[(self.alphabet.index(char) + shift) % 26] if char in self.alphabet else char
            for char in text.upper()
        )

    def _vigenere(self, text, key, encrypt=True):
        key_cycle = cycle(key.upper())
        result = []
        for char in text.upper():
            if char in self.alphabet:
                shift = self.alphabet.index(next(key_cycle))
                shift = shift if encrypt else -shift
                result.append(self.alphabet[(self.alphabet.index(char) + shift) % 26])
            else:
                result.append(char)
        return ''.join(result)

    def _substitution(self, text, key, encrypt=True):
        key_map = dict(zip(self.alphabet, key.upper())) if encrypt else dict(zip(key.upper(), self.alphabet))
        return ''.join(key_map.get(char, char) for char in text.upper())

    def _transposition(self, text, key, encrypt=True):
        if encrypt:
            return ''.join(text[i::key] for i in range(key))
        else:
            num_columns = (len(text) + key - 1) // key
            plaintext = [''] * num_columns
            col, row = 0, 0
            for char in text:
                plaintext[col] += char
                col = col + 1 if col < num_columns - 1 else 0
                row += col == 0
            return ''.join(plaintext)

    def _create_playfair_matrix(self, key):
        used_letters = set()
        matrix = [char for char in (key.upper() + self.alphabet) if char not in used_letters and not used_letters.add(char)]
        return [matrix[i:i + 5] for i in range(0, 25, 5)]

    def _find_position(self, matrix, char):
        for row_idx, row in enumerate(matrix):
            if char in row:
                return row_idx, row.index(char)

    def _playfair(self, text, key, encrypt=True):
        matrix = self._create_playfair_matrix(key)
        text = text.upper().replace('J', 'I').replace(" ", "")
        text += 'X' if len(text) % 2 else ''

        pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
        result = []

        for a, b in pairs:
            row_a, col_a = self._find_position(matrix, a)
            row_b, col_b = self._find_position(matrix, b)
            if row_a == row_b:  # Same row
                result.extend([matrix[row_a][(col_a + (1 if encrypt else -1)) % 5],
                               matrix[row_b][(col_b + (1 if encrypt else -1)) % 5]])
            elif col_a == col_b:  # Same column
                result.extend([matrix[(row_a + (1 if encrypt else -1)) % 5][col_a],
                               matrix[(row_b + (1 if encrypt else -1)) % 5][col_b]])
            else:  # Rectangle
                result.extend([matrix[row_a][col_b], matrix[row_b][col_a]])
        return ''.join(result)

    def _enigma(self, text, key, encrypt=True):
        rotor = cycle(key.upper())
        return ''.join(
            self.alphabet[(self.alphabet.index(char) + (self.alphabet.index(next(rotor)) if encrypt else -self.alphabet.index(next(rotor)))) % 26]
            if char in self.alphabet else char for char in text.upper()
        )


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
