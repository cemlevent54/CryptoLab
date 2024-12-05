import time
import random
import tracemalloc
import matplotlib.pyplot as plt
from collections import Counter


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
        data_copy = data[:]  # Girdinin değiştirilmesini önlemek için kopya alınır
        start_time = time.perf_counter()
        algo(data_copy)
        end_time = time.perf_counter()
        return end_time - start_time

    def frequency_analysis(self, output):
        """
        Performs frequency analysis on the output of the algorithm.
        :param output: Output string of the algorithm.
        :return: Frequency analysis score.
        """
        freq = Counter(output)
        return sum(freq.values()) / len(freq)

    def brute_force_time(self, key_space_size):
        """
        Estimates the brute-force time for a given key space size.
        :param key_space_size: Number of possible keys.
        :return: Estimated brute-force time in seconds.
        """
        brute_force_rate = 1000000  # Assume 1M keys/sec cracking speed
        return key_space_size / brute_force_rate

    def memory_usage(self, algo, data):
        """
        Estimates the memory usage of the algorithm using tracemalloc.
        :param algo: Algorithm function.
        :param data: Input data for the algorithm.
        :return: Memory usage in kilobytes.
        """
        data_copy = data[:]  # Girdinin değiştirilmesini önlemek için kopya alınır
        tracemalloc.start()
        algo(data_copy)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return peak / 1024  # Convert bytes to kilobytes

    def compare_algorithms(self, data, key_space_size):
        """
        Compares the two algorithms on various metrics.
        :param data: Input data to process.
        :param key_space_size: Key space size for brute-force estimation.
        :return: Comparison results.
        """
        results = {
            "algo1_performance": self.measure_performance(self.algo1, data),
            "algo2_performance": self.measure_performance(self.algo2, data),
            "algo1_frequency": self.frequency_analysis(self.algo1(data[:])),
            "algo2_frequency": self.frequency_analysis(self.algo2(data[:])),
            "algo1_brute_force": self.brute_force_time(key_space_size),
            "algo2_brute_force": self.brute_force_time(key_space_size),
            "algo1_memory": self.memory_usage(self.algo1, data),
            "algo2_memory": self.memory_usage(self.algo2, data),
        }
        return results

    def plot_results(self, results):
        """
        Plots all comparison results separately.
        :param results: Dictionary of comparison results.
        """
        metrics = ["Performance", "Frequency", "Brute-Force Time", "Memory Usage"]
        algo1_scores = [
            results["algo1_performance"],
            results["algo1_frequency"],
            results["algo1_brute_force"],
            results["algo1_memory"],
        ]
        algo2_scores = [
            results["algo2_performance"],
            results["algo2_frequency"],
            results["algo2_brute_force"],
            results["algo2_memory"],
        ]

        plt.figure(figsize=(12, 6))
        for i, metric in enumerate(metrics):
            plt.subplot(2, 2, i + 1)
            plt.bar(["Algorithm 1", "Algorithm 2"], [algo1_scores[i], algo2_scores[i]], color=['blue', 'orange'])
            plt.title(f"{metric} Comparison")
            plt.ylabel(metric)
        plt.tight_layout()
        plt.show()


# Define multiple algorithms
def caesar_cipher(text):
    shift = 3
    return "".join(chr((ord(c) - 65 + shift) % 26 + 65) if c.isalpha() else c for c in text.upper())

def vigenere_cipher(text):
    key = "KEY"
    result = []
    for i, char in enumerate(text.upper()):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - 65
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        else:
            result.append(char)
    return "".join(result)

def random_shuffle(data):
    random.seed(42)  # Sabit bir başlangıç durumu belirliyoruz
    return "".join(random.sample(data, len(data)))


# Main function
if __name__ == "__main__":
    # Algorithm map for dynamic selection
    algorithm_map = {
        "Caesar Cipher": caesar_cipher,
        "Vigenere Cipher": vigenere_cipher,
        "Random Shuffle": random_shuffle,
    }

    # User selection
    algo1_name = "Random Shuffle"
    algo2_name = "Random Shuffle"  # Aynı algoritmayı seçiyoruz

    # Initialize comparator with selected algorithms
    algo1 = algorithm_map[algo1_name]
    algo2 = algorithm_map[algo2_name]

    comparator = AlgorithmComparator(algo1, algo2)

    # Define test data and key space
    test_data = list("exampledatafortestingalgorithms")  # Liste olarak işlenebilir

    key_space = 2 ** 16

    # Compare algorithms
    results = comparator.compare_algorithms(test_data, key_space)

    # Print comparison results
    print("\nComparison Results:")
    for key, value in results.items():
        if "memory" in key:
            print(f"{key}: {value:.10f} KB")
        else:
            print(f"{key}: {value}")

    # Plot results
    comparator.plot_results(results)
