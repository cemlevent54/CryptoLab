import time 
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc
import math

from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper



class SymmetricAlgorithmComparator():
    def __init__(self, algo1,algo2):
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
        performance_helper = MeasurePerformanceHelper()
        return performance_helper.measure_performance(algo, data,100)
    
    def frequency_analysis(self, output):
        """
        Calculates the Shannon Entropy for the given output.

        :param output: Output string (or byte output) of the encryption algorithm.
        :return: Shannon Entropy value.
        """
        frequency_helper = MeasureFrequencyHelper()
        return frequency_helper.calculate_shannon_entropy(output)
    
    def memory_usage(self, algo, data):
        """
        Estimates the peak memory usage of the algorithm with warm-up phase using tracemalloc.
        :param algo: Algorithm function.
        :param data: Input data for the algorithm.
        :return: Peak memory usage in kilobytes.
        """
        memory_helper = MeasureMemoryUsageHelper()
        return memory_helper.memory_usage(algo, data)
    
    def compare_algorithms(self, data, key_space_size):
        """
        Compares the two algorithms on various metrics.
        :param data: Input data to process.
        :param key_space_size: Key space size for brute-force estimation.
        :return: Comparison results.
        """
        results = {}

        # Performance
        results["algo1_performance"] = self.measure_performance(self.algo1, data)
        results["algo2_performance"] = self.measure_performance(self.algo2, data)
        # print efficient result for performance
        if results["algo1_performance"] < results["algo2_performance"]:
            print("Algorithm 1 is more efficient.",results["algo1_performance"],results["algo2_performance"])
        else:
            print("Algorithm 2 is more efficient.",results["algo1_performance"],results["algo2_performance"])
        # Frequency analysis
        algo1_encrypted = self.algo1(data)
        algo2_encrypted = self.algo2(data)
        # print length of encrypted data
        print("Algo1_encrypted:",algo1_encrypted)
        print("Algo2_encrypted:",algo2_encrypted)
        print("Length of encrypted data for algo1:",len(algo1_encrypted))
        print("Length of encrypted data for algo2:",len(algo2_encrypted))
        results["algo1_frequency"] = self.frequency_analysis(algo1_encrypted)
        results["algo2_frequency"] = self.frequency_analysis(algo2_encrypted)
        # print efficient result for frequency
        if results["algo1_frequency"] < results["algo2_frequency"]:
            print("Algorithm 1 is more efficient.",results["algo1_frequency"],results["algo2_frequency"])
        else:
            print("Algorithm 2 is more efficient.",results["algo1_frequency"],results["algo2_frequency"])

        # Memory usage
        results["algo1_memory"] = self.memory_usage(self.algo1, data)
        results["algo2_memory"] = self.memory_usage(self.algo2, data)
        # print efficient result for memory
        if results["algo1_memory"] < results["algo2_memory"]:
            print("Algorithm 1 is more efficient.",results["algo1_memory"],results["algo2_memory"])
        else:
            print("Algorithm 2 is more efficient.",results["algo1_memory"],results["algo2_memory"])
        return results
    
    