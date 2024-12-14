from collections import Counter
import math

class EntropyCalculator:
    def frequency_analysis(self, output):
        if not output:
            return 0
        
        freq = Counter(output)
        total = len(output)
        entropy = 0

        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

# Test
calculator = EntropyCalculator()

data1 = "AAAAAA"  # Çok düzenli veri
data2 = "ABCABC"  # Orta düzenli veri
data3 = "K7&3j$Qw"  # Rastgele veri

print("Entropy for 'AAAAAA':", calculator.frequency_analysis(data1))
print("Entropy for 'ABCABC':", calculator.frequency_analysis(data2))
print("Entropy for 'K7&3j$Qw':", calculator.frequency_analysis(data3))
