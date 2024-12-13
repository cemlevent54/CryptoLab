import time
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc
import math
import os
from Crypto.Cipher import DES3
from AsymmetricAlgorithms.AsymmetricEncryptionAlgorithms import AsymmetricEncryptionAlgorithms
from SymmetricAlgorithms.SymmetricEncryptionAlgorithms import SymmetricEncryptionAlgorithms

class SymmetricHybridComparator():
    def __init__(self,symmetric_algo,hybrid_algo):
        self.symmetric_algo = symmetric_algo
        self.hybrid_algo = hybrid_algo
        
    def measure_performance_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        print(f"algo: {algo}")
        total_time = 0
        iterations = 3
        
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
    
    def measure_performance_for_hybrid_algo(self,data):
        algo = self.hybrid_algo
        print(f"algo: {algo}")
        
        total_time = 0
        iterations = 3
        
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
    
    def measure_frequency_analysis_for_symmetric_algo(self,output):
        # shannon entropy
        algo = self.symmetric_algo
        
        if not output:
            return 0
        
        freq = Counter(output)
        total = len(output)
        entropy = 0
        
        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def measure_frequency_analysis_for_hybrid_algo(self,output):
        # shannon entropy
        algo = self.hybrid_algo
        
        if not output:
            return 0
        
        freq = Counter(output)
        total = len(output)
        entropy = 0
        
        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def measure_memory_usage_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        
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
    
    def measure_memory_usage_for_hybrid_algo(self,data):
        algo = self.hybrid_algo
        
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
    
    def compare_algorithms(self,data):
        results = {}
        
        algo1_performance = self.measure_performance_for_symmetric_algo(data)
        algo2_performance = self.measure_performance_for_hybrid_algo(data)
        
        if algo1_performance < algo2_performance:
            print("Symmetric algorithm is more efficient",algo1_performance,algo2_performance)
            
        else:
            print("Hybrid algorithm is more efficient",algo1_performance,algo2_performance)
        
        algo1_encrypted = self.symmetric_algo(data)
        algo2_encrypted = self.hybrid_algo(data)["ciphertext"]
        print("Length of encrypted data for algo1:", len(algo1_encrypted))
        print("Length of encrypted data for algo2:", len(algo2_encrypted))
        
        
        
        algo1_frequency = self.measure_frequency_analysis_for_symmetric_algo(algo1_encrypted)
        algo2_frequency = self.measure_frequency_analysis_for_hybrid_algo(algo2_encrypted)
        
        if algo1_frequency < algo2_frequency:
            print("Symmetric algorithm is more secure",algo1_frequency,algo2_frequency)
        else:
            print("Hybrid algorithm is more secure",algo1_frequency,algo2_frequency)
        
        algo1_memory = self.measure_memory_usage_for_symmetric_algo(data)
        algo2_memory = self.measure_memory_usage_for_hybrid_algo(data)
        
        if algo1_memory < algo2_memory:
            print("Symmetric algorithm uses less memory",algo1_memory,algo2_memory)
        else:
            print("Hybrid algorithm uses less memory",algo1_memory,algo2_memory)
        
        results.update({
            "algo1_performance": algo1_performance,
            "algo2_performance": algo2_performance,
            "algo1_frequency": algo1_frequency,
            "algo2_frequency": algo2_frequency,
            "algo1_memory": algo1_memory,
            "algo2_memory": algo2_memory
        })
        
        return results
        
    
    
        
    
    