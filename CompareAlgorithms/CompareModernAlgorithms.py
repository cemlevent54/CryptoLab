import time
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc
import math


class ModernAlgorithmComparator():
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
    
    
    def frequency_analysis(self,output):
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
    
    def memory_usage(self, algo, data):
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
    
    def output_size_analysis(self,algo,data):
        """
        Measures the size of the output of the encryption algorithm.

        :param algo: Encryption algorithm function.
        :param data: Input data for the algorithm.
        :return: Size of the output in bytes.
        """
        algo1_size = len(self.algo1(data)["ciphertext"])
        algo2_size = len(self.algo2(data))
        print("Size of encrypted data for algo1:", algo1_size)
        print("Size of encrypted data for algo2:", algo2_size)
        
        return algo1_size
    
    def get_size_of_rsa_pss(self,data):
        algo_size = len(self.algo2(data))
        print("Size of encrypted data for algo2:", algo_size)
        return algo_size
    
    def get_size_of_aes_gcm(self,data):
        algo_size = len(self.algo1(data)["ciphertext"])
        print("Size of encrypted data for algo1:", algo_size)
        return algo_size
        
    
    def compare_algorithms(self,data,key_space):
        """
        Compares the performance, memory usage, and entropy of the two algorithms.

        :param data: Input data for the algorithm.
        :param key_space: Key space for the algorithm.
        :return: A dictionary containing the comparison results.
        """
        results = {}
        
        # Algoritma 1 performans ölçümü
        results["algo1_performance"] = self.measure_performance(self.algo1, data)
        results["algo2_performance"] = self.measure_performance(self.algo2, data)
        if results["algo1_performance"] < results["algo2_performance"]:
            print("Algorithm 1 is more efficient.", results["algo1_performance"], results["algo2_performance"])
        else:
            print("Algorithm 2 is more efficient.", results["algo1_performance"], results["algo2_performance"])
        
        # frequency analysis
        algo1_encrypted = self.algo1(data)["ciphertext"]
        algo2_encrypted = self.algo2(data)
        
        print("Length of encrypted data for algo1:", len(algo1_encrypted))
        print("Length of encrypted data for algo2:", len(algo2_encrypted))
        
        algo1_size = self.get_size_of_aes_gcm(data)
        algo2_size = self.get_size_of_rsa_pss(data)
        
        results["algo1_size"] = algo1_size
        results["algo2_size"] = algo2_size
        if results["algo1_size"] < results["algo2_size"]:
            print("Algorithm 1 is more secure.", results["algo1_size"], results["algo2_size"])
        else:
            print("Algorithm 2 is more secure.", results["algo1_size"], results["algo2_size"])
            
        # memory usage
        results["algo1_memory"] = self.memory_usage(self.algo1, data)
        results["algo2_memory"] = self.memory_usage(self.algo2, data)
        if results["algo1_memory"] < results["algo2_memory"]:
            print("Algorithm 1 uses less memory.", results["algo1_memory"], results["algo2_memory"])
        else:
            print("Algorithm 2 uses less memory.", results["algo1_memory"], results["algo2_memory"])
        
        return results
        
    def plot_performance(self,results):
        """
        Plots the performance comparison of the algorithms.
        :param results: Dictionary of comparison results.
        """
        plt.figure(figsize=(6, 4))
        plt.bar(["Algorithm 1", "Algorithm 2"], 
                [results["algo1_performance"], results["algo2_performance"]], 
                color=['blue', 'orange'])
        plt.title("Performance Comparison")
        plt.ylabel("Execution Time (seconds)")
        plt.xlabel("Algorithms")
        plt.tight_layout()
        plt.show()
    
    def plot_frequency(self,results):
        """
        Plots the frequency comparison of the algorithms.
        :param results: Dictionary of comparison results.
        """
        plt.figure(figsize=(6, 4))
        plt.bar(["Algorithm 1", "Algorithm 2"], 
                [results["algo1_frequency"], results["algo2_frequency"]], 
                color=['green', 'purple'])
        plt.title("Frequency Analysis Comparison")
        plt.ylabel("Frequency Score")
        plt.xlabel("Algorithms")
        plt.tight_layout()
        plt.show()
    
    def plot_memory(self,results):
        """
        Plots the memory usage comparison of the algorithms in KB with .10f format.
        :param results: Dictionary of comparison results.
        """
        # Algoritmaların bellek kullanım değerlerini alın
        memory_algo1 = results["algo1_memory"]
        memory_algo2 = results["algo2_memory"]

        # Grafikte gösterilecek etiketleri ayarla (kilobayt cinsinden .10f formatında)
        labels = [f"{memory_algo1:.10f} KB", f"{memory_algo2:.10f} KB"]

        # Grafik oluşturma
        plt.figure(figsize=(6, 4))
        bars = plt.bar(["Algorithm 1", "Algorithm 2"], [memory_algo1, memory_algo2], color=['magenta', 'yellow'], alpha=0.8)
        plt.title("Memory Usage Comparison (KB)")
        plt.ylabel("Memory Usage (KB)")
        plt.xlabel("Algorithms")
        plt.tight_layout()

        # Çubukların üstüne bellek kullanım değerlerini ekle
        for bar, label in zip(bars, labels):
            plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1, label, ha='center', va='bottom')

        # Grafiği göster
        plt.show()
    