if not mapped_symmetric_algorithm or not mapped_asymmetric_algorithm:
            QMessageBox.warning(self, "Selection Error", "Please select both algorithms to compare.")
            return

        print(f"Mapped Symmetric Algorithm: {mapped_symmetric_algorithm}")
        print(f"Mapped Asy