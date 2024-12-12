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

class SymmetricAsymmetricComparator():
    def __init__(self,symmetric_algo,asymmetric_algo):
        self.symmetric_algo = symmetric_algo
        self.asymmetric_algo = asymmetric_algo
        
    
    def measure_performance_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        print(f"algo: {algo}")
        total_time = 0
        iterations = 1
        
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
    
    def measure_performance_for_asymmetric_algo(self,data):
        algo = self.asymmetric_algo
        print(f"algo: {algo}")
        
        total_time = 0
        iterations = 1
        
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
    
    def measure_frequency_analysis_for_asymmetric_algo(self,output):
        algo = self.asymmetric_algo
        
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
    
    def measure_memory_usage_for_asymmetric_algo(self,data):
        algo = self.asymmetric_algo
        
        tracemalloc.start()
        
        algo(data)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        memory_used = peak / 1024
        return memory_used
    
    
    
    def compare_algorithms(self, data):
        results = {}
        # Performans ölçümü
        algo1_performance = self.measure_performance_for_symmetric_algo(data)
        algo2_performance = self.measure_performance_for_asymmetric_algo(data)

        if algo1_performance < algo2_performance:
            print("Symmetric Algorithm is more efficient.", algo1_performance, algo2_performance)
        else:
            print("Asymmetric Algorithm is more efficient.", algo1_performance, algo2_performance)

        # Performans sonuçlarını ekle
        results.update({
            "algo1_performance": algo1_performance,
            "algo2_performance": algo2_performance
        })

        # Şifreleme uzunluklarını tutmak için

        
        
        # Bellek kullanımı ölçümü
        algo1_memory = self.measure_memory_usage_for_symmetric_algo(data)
        algo2_memory = self.measure_memory_usage_for_asymmetric_algo(data)

        if algo1_memory < algo2_memory:
            print("Symmetric Algorithm is more efficient in memory usage.", algo1_memory, algo2_memory)
        else:
            print("Asymmetric Algorithm is more efficient in memory usage.", algo1_memory, algo2_memory)

        # Sonuçları güncelle
        results.update({
            "algo1_performance": algo1_performance * 1000,
            "algo2_performance": algo2_performance * 1000,
            "algo1_memory": algo1_memory,
            "algo2_memory": algo2_memory,
            "algo1_length" : 0,
            "algo2_length" : 0
        })

        return results
