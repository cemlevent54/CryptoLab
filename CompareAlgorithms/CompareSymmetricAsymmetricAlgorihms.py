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

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()

class SymmetricAsymmetricComparator():
    def __init__(self,symmetric_algo,asymmetric_algo):
        self.symmetric_algo = symmetric_algo
        self.asymmetric_algo = asymmetric_algo
        
    
    def measure_performance_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        print(f"algo: {algo}")
        return measure_performance_helper.measure_performance(algo,data,1)
    
    def measure_performance_for_asymmetric_algo(self,data):
        algo = self.asymmetric_algo
        print(f"algo: {algo}")
        
        return measure_performance_helper.measure_performance(algo,data,1)
        
    def measure_frequency_analysis_for_symmetric_algo(self,output):
        algo = self.symmetric_algo
        if not output:
            return 0
        
        return measure_frequency_helper.calculate_shannon_entropy(output)
    
    def measure_frequency_analysis_for_asymmetric_algo(self,output):
        algo = self.asymmetric_algo
        
        if not output:
            return 0
        
        return measure_frequency_helper.calculate_shannon_entropy(output)
    
    def measure_memory_usage_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        
        return measure_memory_usage_helper.memory_usage(algo,data)
    
    def measure_memory_usage_for_asymmetric_algo(self,data):
        algo = self.asymmetric_algo
        
        return measure_memory_usage_helper.memory_usage(algo,data)
    
    
    
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
