
    
    

from collections import Counter
import math
#######

class MeasureFrequencyHelper:
    def __init__(self):
        # English letter frequency (normalized)
        self.english_freq = {
            'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 13.0, 'F': 2.2,
            'G': 2.0, 'H': 6.1, 'I': 7.0, 'J': 0.15, 'K': 0.77, 'L': 4.0,
            'M': 2.4, 'N': 6.7, 'O': 7.5, 'P': 1.9, 'Q': 0.095, 'R': 6.0,
            'S': 6.3, 'T': 9.1, 'U': 2.8, 'V': 0.98, 'W': 2.4, 'X': 0.15,
            'Y': 2.0, 'Z': 0.074
        }

    def calculate_chi_squared(self, data):
        """
        Chi-Squared hesaplama: Frekans analizini yaparak veri gizliliğini ölçer.
        """
        output_freq = Counter(data.upper())
        total_chars = sum(output_freq.values())

        if total_chars == 0:
            return float('inf')

        chi_squared = sum(
            (((output_freq.get(letter, 0) / total_chars * 100) - expected_freq) ** 2) / expected_freq
            for letter, expected_freq in self.english_freq.items()
        )
        return chi_squared

    def calculate_shannon_entropy(self, output):
        """
        Shannon Entropy hesaplama: Verinin rastgeleliğini ölçer.
        """
        if not output:
            return 0  # Eğer veri boşsa, Entropy sıfır döndür
        
        freq = Counter(output)
        total = len(output)
        entropy = 0

        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def calculate_security_score(self, encrypted_data):
        """
        Genel güvenlik skoru hesaplar:
        - Chi-squared analizini normalize eder
        - Shannon entropy ile birleştirir
        """
        chi_squared_score = self.calculate_chi_squared(encrypted_data)
        entropy_score = self.calculate_shannon_entropy(encrypted_data)

        # Normalize Chi-Squared: Düşük değer iyi (0-1 arası normalleştirme)
        normalized_chi = min(1, 1 / (1 + chi_squared_score))
        
        # Shannon Entropy: Rastgelelik ölçümü (8 ideal değer)
        normalized_entropy = min(entropy_score / 8.0, 1)

        # Genel güvenlik skoru: Ortalama skor
        overall_score = (normalized_chi + normalized_entropy) / 2

        return overall_score
    
    def _calculate_shannon_entropy(self, output):
        """
        Shannon Entropy hesaplama algoritması
        :param output: Hesaplanacak veri (string veya bytes)
        :return: float, Shannon entropy değeri
        """
        if not output:
            return 0.0  # Boş veri için entropy 0 döner

        # Bayt dizisine çevirme
        if isinstance(output, str):
            output = output.encode('utf-8')  # String ise bayt dizisine dönüştür

        m = len(output)  # Toplam eleman sayısı
        bases = Counter(output)  # Frekans hesaplama

        shannon_entropy_value = 0.0
        for base in bases:
            n_i = bases[base]  # Eleman sayısı
            if isinstance(n_i, (int, float)):  # Sayısal kontrol
                p_i = n_i / float(m)  # Olasılık hesaplama
                entropy_i = p_i * (math.log2(p_i))  # Entropy değeri
                shannon_entropy_value += entropy_i

        return shannon_entropy_value * -1
    
    
    def get_chi_squared(self,output):
        english_freq = {
            'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 13.0, 'F': 2.2,
            'G': 2.0, 'H': 6.1, 'I': 7.0, 'J': 0.15, 'K': 0.77, 'L': 4.0,
            'M': 2.4, 'N': 6.7, 'O': 7.5, 'P': 1.9, 'Q': 0.095, 'R': 6.0,
            'S': 6.3, 'T': 9.1, 'U': 2.8, 'V': 0.98, 'W': 2.4, 'X': 0.15,
            'Y': 2.0, 'Z': 0.074
        }

        # Calculate output letter frequencies
        output_freq = Counter(output.upper())  # Case-insensitive
        total_chars = sum(output_freq.values())

        if total_chars == 0:
            return float('inf')  # No characters to analyze

        # Calculate Chi-squared score
        chi_squared = sum(
            (((output_freq.get(letter, 0) / total_chars * 100) - expected_freq) ** 2) / expected_freq
            for letter, expected_freq in english_freq.items()
        )

        return chi_squared
    
    def calculate_shannon_entropy(self, output):
        """
        Shannon Entropy hesaplama: Verinin rastgeleliğini ölçer.
        """
        if not output:
            return 0  # Eğer veri boşsa, Entropy sıfır döndür
        
        freq = Counter(output)
        total = len(output)
        entropy = 0

        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy
        
    
    
