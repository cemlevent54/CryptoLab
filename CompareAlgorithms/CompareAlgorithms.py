import time
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc

from Helpers.MeasurePerformanceHelper import MeasurePerformanceHelper
from Helpers.MeasureFrequencyHelper import MeasureFrequencyHelper
from Helpers.MeasureMemoryUsageHelper import MeasureMemoryUsageHelper


class AlgorithmComparator:
    
    def __init__(self, algo1, algo2):
        """
        Constructor for the AlgorithmComparator class.
        :param algo1: First algorithm function.
        :param algo2: Second algorithm function.
        """
        self.algo1 = algo1
        self.algo2 = algo2

    def measure_performance(self, algo, data):
        """
        Measures the average execution time of the algorithm over multiple iterations.
        :param algo: Algorithm function.
        :param data: Input data for the algorithm.
        :param iterations: Number of times the algorithm is executed.
        :return: Average execution time in seconds.
        """
        performance_helper = MeasurePerformanceHelper()
        return performance_helper.measure_performance(algo,data,100)

    def frequency_analysis(self, output):
        """
        Performs frequency analysis on the output of the algorithm using English letter frequency.

        :param output: Output string of the algorithm.
        :return: Chi-squared score indicating how close the output is to natural language frequencies.
        """
        frequency_helper = MeasureFrequencyHelper()
        return frequency_helper.get_chi_squared(output)
        
    

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

        # Frequency analysis
        results["algo1_frequency"] = self.frequency_analysis(self.algo1(data))
        results["algo2_frequency"] = self.frequency_analysis(self.algo2(data))


        # Memory usage
        results["algo1_memory"] = self.memory_usage(self.algo1, data)
        results["algo2_memory"] = self.memory_usage(self.algo2, data)

        return results

    
        


