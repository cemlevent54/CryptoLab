from PyQt5.QtWidgets import QGraphicsScene, QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5 import QtCore
import matplotlib.pyplot as plt

from CompareAlgorithms.CompareAlgorithms import AlgorithmComparator
from OldAlgorithms.OldEncryptionAlgorithms import OldEncryptionAlgorithms




class FormHelper:
    def plot_to_graphicsview(self,graphics_view, title, data1, data2, categories):
        """
        Matplotlib grafiğini QGraphicsView içinde göstermek için.
        :param graphics_view: QGraphicsView bileşeni.
        :param title: Grafik başlığı.
        :param data1: Birinci algoritmanın verileri.
        :param data2: İkinci algoritmanın verileri.
        :param categories: Kategoriler (örneğin: Performans, Güvenlik).
        """
        # Matplotlib grafiğini oluştur
        plt.figure(figsize=(3.5, 2.5))  # QGraphicsView boyutuna uygun bir boyut seç
        x = range(len(categories))
        plt.bar(x, data1, width=0.2, label="Algorithm 1", align="center")
        plt.bar([p + 0.4 for p in x], data2, width=0.2, label="Algorithm 2", align="center")
        plt.xticks([p + 0.2 for p in x], categories)
        plt.xlabel("Metrics")
        plt.ylabel("Scores")
        plt.title(title)
        plt.legend()
        plt.tight_layout()  # Kenar boşluklarını azalt

        # Geçici bir PNG dosyasına kaydet
        temp_file = "temp_graph.png"
        plt.savefig(temp_file, dpi=100)  # DPI'ı düşürerek görüntüye daha fazla yer kazandırabilirsiniz
        plt.close()

        # QGraphicsView içine yükle
        scene = QGraphicsScene()
        pixmap = QPixmap(temp_file)
        scene.addPixmap(pixmap)
        graphics_view.setScene(scene)

        # QGraphicsView içindeki görüntüyü tam boyutta göster
        graphics_view.fitInView(scene.itemsBoundingRect(), QtCore.Qt.KeepAspectRatio)
        
    