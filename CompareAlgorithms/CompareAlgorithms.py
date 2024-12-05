import time
import random
import sys
import matplotlib.pyplot as plt
from collections import Counter
import tracemalloc


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
        Measures the execution time of the algorithm.
        :param algo: Algorithm function.
        :param data: Input data for the algorithm.
        :return: Execution time in seconds.
        """
        start_time = time.perf_counter()
        algo(data)
        end_time = time.perf_counter()
        return end_time - start_time

    def frequency_analysis(self, output):
        """
        Performs frequency analysis on the output of the algorithm.
        :param output: Output string of the algorithm.
        :return: Frequency analysis score.
        """
        freq = Counter(output)
        return sum(freq.values()) / len(freq)  # Simpler score for demonstration

    

    def memory_usage(self, algo, data):
        """
        Estimates the memory usage of the algorithm using tracemalloc.
        :param algo: Algorithm function.
        :param data: Input data for the algorithm.
        :return: Memory usage in kilobytes.
        """
        tracemalloc.start()  # Bellek izlemeyi başlat
        before = tracemalloc.get_traced_memory()[0]  # Başlangıçtaki bellek kullanımı
        algo(data)  # Algoritmayı çalıştır
        after = tracemalloc.get_traced_memory()[0]  # Algoritmadan sonraki bellek kullanımı
        tracemalloc.stop()  # Bellek izlemeyi durdur

        memory_used = (after - before) / 1024  # KB cinsinden bellek kullanımı
        print(f"Memory used: {memory_used:.30f} KB")
        return memory_used

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

    def plot_performance(self, results):
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

    def plot_frequency(self, results):
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

    

    def plot_memory(self, results):
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


    def plot_results(self, results):
        """
        Plots all comparison results separately.
        :param results: Dictionary of comparison results.
        """
        self.plot_performance(results)
        self.plot_frequency(results)
        self.plot_memory(results)
        


# Example usage:
# def sample_algo1(data):
#     return "".join(random.sample(data, len(data)))


# def sample_algo2(data):
#     return "".join(sorted(data))


# comparator = AlgorithmComparator(sample_algo1, sample_algo2)
# test_data = "exampledatafortestingalgorithms"
# key_space = 2 ** 16  # Example key space size
# comparison_results = comparator.compare_algorithms(test_data, key_space)
# comparator.plot_results(comparison_results)
