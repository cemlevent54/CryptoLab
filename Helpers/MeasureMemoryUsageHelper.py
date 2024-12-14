import tracemalloc

class MeasureMemoryUsageHelper():
    def memory_usage(self,algo,data):
        tracemalloc.start()
        # Isınma aşaması (warm-up phase)
        algo(data)
        
        tracemalloc.reset_peak()  # Bellek ölçümlerini sıfırla
        algo(data)  # Algoritmayı çalıştır
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        memory_used = peak / 1024  # Zirve bellek kullanımını KB cinsine çevir
        print(f"Peak Memory used (with warm-up): {memory_used:.3f} KB")
        return memory_used
    