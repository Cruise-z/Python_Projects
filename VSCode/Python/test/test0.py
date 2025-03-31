import cv2
import os
import numpy as np
from scipy.fftpack import dct, idct
from scipy.stats import entropy
from numpy.linalg import svd

def compute_dct(image):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    return dct(dct(gray.T, norm='ortho').T, norm='ortho')

def high_frequency_energy_ratio(dct_matrix, threshold=0.5):
    H, W = dct_matrix.shape
    mask = np.zeros((H, W))
    mask[int(H * threshold):, int(W * threshold):] = 1
    hf_energy = np.sum(np.abs(dct_matrix) * mask)
    total_energy = np.sum(np.abs(dct_matrix))
    return hf_energy / total_energy if total_energy > 0 else 0

def compute_dct_8x8_quantized(image):
    """
    计算 8×8 DCT 并进行 JPEG 量化
    """
    h, w = image.shape
    block_size = 8

    # JPEG 标准亮度量化表（质量 50%）
    Q50 = np.array([[16, 11, 10, 16, 24, 40, 51, 61],
                    [12, 12, 14, 19, 26, 58, 60, 55],
                    [14, 13, 16, 24, 40, 57, 69, 56],
                    [14, 17, 22, 29, 51, 87, 80, 62],
                    [18, 22, 37, 56, 68, 109, 103, 77],
                    [24, 35, 55, 64, 81, 104, 113, 92],
                    [49, 64, 78, 87, 103, 121, 120, 101],
                    [72, 92, 95, 98, 112, 100, 103, 99]])

    # 创建 DCT 结果存储矩阵
    dct_blocks = np.zeros((h, w), dtype=np.float32)

    # 遍历每个 8×8 块
    for i in range(0, h, block_size):
        for j in range(0, w, block_size):
            block = image[i:i+block_size, j:j+block_size].astype(np.float32) - 128
            dct_block = cv2.dct(block)  # 计算 DCT
            quantized_block = np.round(dct_block / Q50)  # 进行 JPEG 量化
            dct_blocks[i:i+block_size, j:j+block_size] = quantized_block

    return dct_blocks

def sparsity_ratio(dct_matrix):
    """
    计算 Sparsity Ratio (SR)，即 DCT 矩阵中 0 的比例
    """
    zero_count = np.sum(np.abs(dct_matrix) < 1e-5)  # 允许浮点误差
    total_elements = dct_matrix.size
    return zero_count / total_elements

def dct_histogram_entropy(dct_matrix):
    hist, _ = np.histogram(dct_matrix, bins=256, range=(-128, 128), density=True)
    return entropy(hist + 1e-10)  # 避免 log(0)

def low_rank_energy(dct_matrix, rank=10):
    U, S, Vt = svd(dct_matrix)
    return np.sum(S[:rank]) / np.sum(S) if np.sum(S) > 0 else 0

def high_frequency_autocorrelation(dct_matrix, tau=1):
    H, W = dct_matrix.shape
    hf_part = dct_matrix[int(H/2):, int(W/2):]  # 取高频部分
    shifted = np.roll(hf_part, shift=tau, axis=0)
    return np.sum(hf_part * shifted) / np.sum(hf_part**2) if np.sum(hf_part**2) > 0 else 0

# 读取图像并计算DCT
def analyze_image(image_path):
    image = cv2.imread(image_path)
    dct_matrix = compute_dct(image)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    dct_matrix_sr = compute_dct_8x8_quantized(gray)
    
    hfer = high_frequency_energy_ratio(dct_matrix)
    sr = sparsity_ratio(dct_matrix_sr)
    entropy_val = dct_histogram_entropy(dct_matrix)
    rank_energy = low_rank_energy(dct_matrix)
    autocorr = high_frequency_autocorrelation(dct_matrix)
    
    print(f"High-Frequency Energy Ratio (HFER): {hfer:.4f}")
    print(f"Sparsity Ratio (SR): {sr:.4f}")
    print(f"DCT Histogram Entropy: {entropy_val:.4f}")
    print(f"Low-Rank Energy (Top 10): {rank_energy:.4f}")
    print(f"High-Frequency Autocorrelation: {autocorr:.4f}")
    
    return {
        "HFER": hfer,
        "Sparsity Ratio": sr,
        "DCT Entropy": entropy_val,
        "Low-Rank Energy": rank_energy,
        "Autocorrelation": autocorr
    }

def dct_analysis(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)

    if img is None:
        print(f"❌ 无法读取图片: {image_path}")
        return

    # 进行 DCT 变换
    dct = cv2.dct(np.float32(img))

    # **增强可视化**
    dct_log = np.log(np.abs(dct) + 1)  # 避免 log(0) 错误
    dct_norm = cv2.normalize(dct_log, None, 0, 255, cv2.NORM_MINMAX)  # 归一化

    # **伪彩色增强可视化**
    dct_colormap = cv2.applyColorMap(np.uint8(dct_norm), cv2.COLORMAP_JET)

    # **调整显示窗口大小**
    display_size = (800, 600)
    img_resized = cv2.resize(img, display_size, interpolation=cv2.INTER_AREA)
    dct_resized = cv2.resize(dct_colormap, display_size, interpolation=cv2.INTER_AREA)

    # **显示**
    cv2.imshow("Original Image", img_resized)
    cv2.imshow("DCT Spectrum", dct_resized)

    cv2.waitKey(0)
    cv2.destroyAllWindows()

num = 10
src = f"./test{num}_src.jpg"
test = f"./test{num}.jpg"
# print("src image inf: ")
# analyze_image(src)
# print("tested image inf: ")
# analyze_image(test)
dct_analysis(src)
