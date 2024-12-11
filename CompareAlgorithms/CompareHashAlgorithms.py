import time
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc
import math

class HashingAlgorithmsComparator():
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
        Measures the memory usage of the encryption algorithm.

        :param algo: Encryption algorithm function.
        :param data: Input data for the algorithm.
        :return: Memory usage in bytes.
        """
        tracemalloc.start()
        algo(data)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak
    
    def compare_algorithms(self, data,key_space):
        results = {}
        
        results["algo1_performance"] = self.measure_performance(self.algo1, data)
        results["algo2_performance"] = self.measure_performance(self.algo2, data)
        
        if results["algo1_performance"] < results["algo2_performance"]:
            print("Algorithm 1 is more efficienct.",results["algo1_performance"],results["algo2_performance"])
        else:
            print("Algorithm 2 is more efficienct.",results["algo1_performance"],results["algo2_performance"])
            
        algo1_hashed = self.algo1(data)
        algo2_hashed = self.algo2(data)
        
        print("Length of the hash value for algo1:",len(algo1_hashed))
        print("Length of the hash value for algo2:",len(algo2_hashed))
        
        results["algo1_frequency"] = self.frequency_analysis(algo1_hashed)
        results["algo2_frequency"] = self.frequency_analysis(algo2_hashed)
        
        if results["algo1_frequency"] > results["algo2_frequency"]:
            print("Algorithm 1 is more secure.",results["algo1_frequency"],results["algo2_frequency"])
        else:
            print("Algorithm 2 is more secure.",results["algo1_frequency"],results["algo2_frequency"])
            
        results["algo1_memory"] = self.memory_usage(self.algo1, data)
        results["algo2_memory"] = self.memory_usage(self.algo2, data)
        if results["algo1_memory"] < results["algo2_memory"]:
            print("Algorithm 1 uses less memory.",results["algo1_memory"],results["algo2_memory"])
        else:
            print("Algorithm 2 uses less memory.",results["algo1_memory"],results["algo2_memory"])
            
        return results
    
    