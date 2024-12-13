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

class ModernOldComparator():
    def __init__(self,modern_algo,old_algo):
        self.modern_algo = modern_algo
        self.old_algo = old_algo
    
    def measure_performance_for_modern_algo(self,data):
        algo = self.modern_algo
        print(f"algo: {algo}")
        total_time = 0
        iterations = 3
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            algo(data)
            end_time = time.perf_counter()
            total_time += (end_time - start_time)
        
        return total_time / iterations
    
    def measure_performance_for_old_algo(self,data):
        algo = self.old_algo
        print(f"algo: {algo}")
        
        total_time = 0
        iterations = 3
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            algo(data)
            end_time = time.perf_counter()
            total_time += (end_time - start_time)
        
        return total_time / iterations
    
    def measure_frequency_analysis_for_modern_algo(self, output):
        """
        Modern algoritmalar için Shannon Entropy hesaplama
        """
        return self._calculate_shannon_entropy(output)

    def measure_frequency_analysis_for_old_algo(self, output):
        """
        Eski algoritmalar için Shannon Entropy hesaplama
        """
        return self._calculate_shannon_entropy(output)

    #!/usr/bin/env python3
# -*- coding: utf-8 -*-



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

    
    def measure_memory_usage_for_modern_algo(self,data):
        algo = self.modern_algo
        
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
    
    def measure_memory_usage_for_old_algo(self,data):
        algo = self.old_algo
        
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
        
        algo1_performance = self.measure_performance_for_modern_algo(data)
        algo2_performance = self.measure_performance_for_old_algo(data)
        
        if algo1_performance < algo2_performance:
            print("Modern algorithm is faster")
        else:
            print("Old algorithm is faster")
        
        algo1_encrypted = self.modern_algo(data)
        algo2_encrypted = self.old_algo(data)
        print("length of algo1_encrypted: ",len(algo1_encrypted))
        print("length of algo2_encrypted: ",len(algo2_encrypted))
        
        algo1_frequency = self.measure_frequency_analysis_for_modern_algo(algo1_encrypted)
        algo2_frequency = self.measure_frequency_analysis_for_old_algo(algo2_encrypted)
        
        if algo1_frequency < algo2_frequency:
            print("Modern algorithm is more secure")
        else:
            print("Old algorithm is more secure")
            
        algo1_memory = self.measure_memory_usage_for_modern_algo(data)
        algo2_memory = self.measure_memory_usage_for_old_algo(data)
        
        if algo1_memory < algo2_memory:
            print("Modern algorithm uses less memory")
        else:
            print("Old algorithm uses less memory")
            
        results.update({
            "algo1_performance":algo1_performance,
            "algo2_performance":algo2_performance,
            "algo1_frequency":algo1_frequency,
            "algo2_frequency":algo2_frequency,
            "algo1_memory":algo1_memory,
            "algo2_memory":algo2_memory
        })
        
        return results
        