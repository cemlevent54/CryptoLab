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

from Helpers.FormHelper import FormHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper
from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper

form_helper = FormHelper()
measure_frequency_helper = MeasureFrequencyHelper()
measure_memory_usage_helper = MeasureMemoryUsageHelper()
measure_performance_helper = MeasurePerformanceHelper()

class ModernOldComparator():
    def __init__(self,modern_algo,old_algo):
        self.modern_algo = modern_algo
        self.old_algo = old_algo
    
    def measure_performance_for_modern_algo(self,data):
        algo = self.modern_algo
        print(f"algo: {algo}")
        return measure_performance_helper.measure_performance(algo,data,10)
    
    def measure_performance_for_old_algo(self,data):
        algo = self.old_algo
        print(f"algo: {algo}")
        
        total_time = 0
        iterations = 3
        
        return measure_performance_helper.measure_performance(algo,data,3)
    
    def measure_frequency_analysis_for_modern_algo(self, output):
        """
        Modern algoritmalar için Shannon Entropy hesaplama
        """
        return measure_frequency_helper._calculate_shannon_entropy(output)

    def measure_frequency_analysis_for_old_algo(self, output):
        """
        Eski algoritmalar için Shannon Entropy hesaplama
        """
        return measure_frequency_helper._calculate_shannon_entropy(output)

   



    

    
    def measure_memory_usage_for_modern_algo(self,data):
        algo = self.modern_algo
        
        return measure_memory_usage_helper.memory_usage(algo,data)
    
    def measure_memory_usage_for_old_algo(self,data):
        algo = self.old_algo
        
        return measure_memory_usage_helper.memory_usage(algo,data)
    
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
        