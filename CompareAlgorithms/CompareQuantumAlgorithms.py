import time
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc
import math

class QuantumAlgorithmComparator():
    def __init__(self,algo1,algo2):
        self.algo1 = algo1
        self.algo2 = algo2
        
    def measure_performance(self, algo, data):
        """
        Measures the average execution time of the encryption algorithm.

        :param algo: Encryption algorithm function.
        :param data: Input data for the algorithm.
        :param iterations: Number of times the algorithm is executed.
        :return: Average execution time in seconds.
        """
        total_time = 0
        iterations = 10
        for _ in range(iterations):
            # Başlangıç zamanını al
            start_time = time.perf_counter()
            
            # Şifreleme işlemini gerçekleştir
            algo(data)
            
            # Bitiş zamanını al
            end_time = time.perf_counter()
            
            # Toplam süreyi hesapla
            total_time += (end_time - start_time)
        
        # Ortalama süreyi döndür
        return total_time / iterations
    
    def frequency_analysis(self, output):
        """
        Calculates the Shannon Entropy for the given output.

        :param output: Output string (or byte output) of the encryption algorithm.
        :return: Shannon Entropy value.
        """
        if not output:
            return 0
        
        freq = Counter(output)
        total = len(output)
        entropy = 0
        
        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def memory_usage(self,algo,data):
        """
        Estimates the peak memory usage of the algorithm with warm-up phase using tracemalloc.
        :param algo: Algorithm function.
        :param data: Input data for the algorithm.
        :return: Peak memory usage in kilobytes.
        """
        tracemalloc.start()
        # Isınma aşaması (warm-up phase)
        algo(data)
        
        tracemalloc.reset_peak()  # Bellek ölçümlerini sıfırla
        algo(data)  # Algoritmayı çalıştır
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        memory_used = peak / 1024  # Zirve bellek kullanımını KB cinsine çevir
        # print(f"Peak Memory used (with warm-up): {memory_used:.3f} KB")
        return memory_used
    
    def compare_algorithms(self,data,key_space):
        results = {}
        
        # Performance
        results["algo1_performance"] = self.measure_performance(self.algo1, data)
        results["algo2_performance"] = self.measure_performance(self.algo2, data)
        
        # Frequency Analysis
        algo1_encrypted = self.algo1(data)
        algo2_encrypted = self.algo2(data)
        print("Length of encrypted data for algo1:", len(algo1_encrypted))
        print("Length of encrypted data for algo2:", len(algo2_encrypted))
        
        results["algo1_frequency"] = self.frequency_analysis(algo1_encrypted)
        results["algo2_frequency"] = self.frequency_analysis(algo2_encrypted)
        if results["algo1_frequency"] < results["algo2_frequency"]:
            print("Algorithm 1 is more secure.", results["algo1_frequency"], results["algo2_frequency"])
        else:
            print("Algorithm 2 is more secure.", results["algo1_frequency"], results["algo2_frequency"])
        
        # memory usage
        results["algo1_memory"] = self.memory_usage(self.algo1, data)
        results["algo2_memory"] = self.memory_usage(self.algo2, data)
        
        if results["algo1_memory"] < results["algo2_memory"]:
            print("Algorithm 1 uses less memory.", results["algo1_memory"], results["algo2_memory"])
        else:
            print("Algorithm 2 uses less memory.", results["algo1_memory"], results["algo2_memory"])
        
        return results
    
    
    