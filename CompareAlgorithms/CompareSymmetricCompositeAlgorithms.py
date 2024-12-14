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

class SymmetricHybridComparator():
    def __init__(self,symmetric_algo,hybrid_algo):
        self.symmetric_algo = symmetric_algo
        self.hybrid_algo = hybrid_algo
        
    def measure_performance_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        print(f"algo: {algo}")
        return measure_performance_helper.measure_performance(algo,data,3)
    
    def measure_performance_for_hybrid_algo(self,data):
        algo = self.hybrid_algo
        print(f"algo: {algo}")
        
        return measure_performance_helper.measure_performance(algo,data,3)
    
    def measure_frequency_analysis_for_symmetric_algo(self,output):
        # shannon entropy
        algo = self.symmetric_algo
        
        if not output:
            return 0
        
        return measure_frequency_helper.calculate_shannon_entropy(output)
    
    def measure_frequency_analysis_for_hybrid_algo(self,output):
        # shannon entropy
        algo = self.hybrid_algo
        
        if not output:
            return 0
        
        return measure_frequency_helper.calculate_shannon_entropy(output)
    
    def measure_memory_usage_for_symmetric_algo(self,data):
        algo = self.symmetric_algo
        
        return measure_memory_usage_helper.memory_usage(algo,data)
    
    def measure_memory_usage_for_hybrid_algo(self,data):
        algo = self.hybrid_algo
        
        return measure_memory_usage_helper.memory_usage(algo,data)
        
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
        
    
    
        
    
    