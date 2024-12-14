import time


class MeasurePerformanceHelper:
    def measure_performance(self,algo,data,iterations=10):
        total_time = 0
        for _ in range(iterations):
            start_time = time.perf_counter()
            algo(data)
            end_time = time.perf_counter()
            total_time += (end_time - start_time)
    
        # Ortalama süreyi döndür
        return total_time / iterations
    
    

    