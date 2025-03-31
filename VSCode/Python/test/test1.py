import numpy as np
import matplotlib.pyplot as plt
from scipy.linalg import svd
from skimage import io, color
from skimage.transform import resize
from skimage.restoration import denoise_tv_chambolle  # 用于去噪
from skimage.metrics import peak_signal_noise_ratio as psnr
from skimage.metrics import structural_similarity as ssim
from sklearn.metrics import mean_squared_error as mse

def resize_image(image, target_shape):
    resized_image = resize(image, target_shape, anti_aliasing=True)
    # 强制转换为灰度图像（如果是彩色图像）并转换为浮动格式（0-255的范围转为0-1）
    if resized_image.ndim == 3:  # 如果是RGB图像
        resized_image = color.rgb2gray(resized_image).astype(np.float64)
    return resized_image

def embed_watermark(original_img, watermark_img, alpha=0.1):
    # 对水印图像和原图进行SVD分解
    U_o, S_o, Vt_o = svd(original_img, full_matrices=False)
    U_w, S_w, Vt_w = svd(watermark_img, full_matrices=False)
    
    # 控制水印嵌入大小（alpha控制水印强度）
    min_size = min(len(S_o), len(S_w))  # 找到两个奇异值的最小尺寸
    S_o[:min_size] += alpha * S_w[:min_size]
    
    # 重构带水印的图像
    watermarked_img = np.dot(U_o, np.dot(np.diag(S_o), Vt_o))
    
    return watermarked_img, U_o, S_o, Vt_o, U_w, S_w, Vt_w

def extract_watermark(watermarked_img, original_S, U_w, Vt_w, alpha=0.1):
    # 对带水印图像进行SVD分解
    U_w_new, S_w_new, Vt_w_new = svd(watermarked_img, full_matrices=False)
    
    # 提取水印的奇异值
    min_size = min(len(S_w_new), len(original_S))  # 取最小尺寸
    extracted_S = (S_w_new[:min_size] - original_S[:min_size]) / alpha
    
    # 为了确保U_w和Vt_w维度匹配，需要调整它们的维度
    U_w_resized = U_w[:, :len(extracted_S)]
    Vt_w_resized = Vt_w[:len(extracted_S), :]
    
    # 重构水印图像
    extracted_watermark = np.dot(U_w_resized, np.dot(np.diag(extracted_S), Vt_w_resized))
    
    # 图像去噪
    extracted_watermark_denoised = denoise_tv_chambolle(extracted_watermark, weight=0.1)
    
    return extracted_watermark_denoised

def display_images(original_img, watermarked_img, extracted_watermark, watermark_img):
    # 显示原图、水印图像和提取的水印，同时也显示实际水印图像用于对比
    plt.figure(figsize=(20, 10))
    
    # 原始图像
    plt.subplot(1, 4, 1)
    plt.imshow(original_img, cmap='gray')
    plt.title("Original Image")
    
    # 带水印的图像
    plt.subplot(1, 4, 2)
    plt.imshow(watermarked_img, cmap='gray')
    plt.title("Watermarked Image")
    
    # 提取的水印图像
    plt.subplot(1, 4, 3)
    plt.imshow(extracted_watermark, cmap='gray')
    plt.title("Extracted Watermark")
    
    # 实际水印图像
    plt.subplot(1, 4, 4)
    plt.imshow(watermark_img, cmap='gray')
    plt.title("Actual Watermark")
    
    plt.show()

def calculate_metrics(original_img, watermarked_img, extracted_watermark, watermark_img):
    # 调整图像尺寸确保一致性
    target_shape = (min(original_img.shape[0], watermarked_img.shape[0], extracted_watermark.shape[0]),
                    min(original_img.shape[1], watermarked_img.shape[1], extracted_watermark.shape[1]))
    original_img_resized = resize_image(original_img, target_shape)
    watermarked_img_resized = resize_image(watermarked_img, target_shape)
    extracted_watermark_resized = resize_image(extracted_watermark, target_shape)
    watermark_img_resized = resize_image(watermark_img, target_shape)

    # 计算PSNR
    psnr_value = psnr(original_img_resized, watermarked_img_resized)
    print(f"PSNR between original and watermarked image: {psnr_value:.2f} dB")

    # 计算SSIM，注意要指定data_range
    ssim_value = ssim(original_img_resized, watermarked_img_resized, data_range=original_img_resized.max() - original_img_resized.min())
    print(f"SSIM between original and watermarked image: {ssim_value:.4f}")
    
    # 计算MSE（水印提取的准确度）
    mse_value = mse(watermark_img_resized, extracted_watermark_resized)
    print(f"MSE between actual and extracted watermark: {mse_value:.4f}")
    
    # 计算提取水印与原始水印之间的相关系数（提取水印准确度）
    correlation_value = np.corrcoef(watermark_img_resized.flatten(), extracted_watermark_resized.flatten())[0, 1]
    print(f"Correlation between actual and extracted watermark: {correlation_value:.4f}")


def test_robustness(watermarked_img, watermark_img, alpha=0.1):
    # 对水印图像进行压缩、噪声和裁剪等操作
    from skimage.util import random_noise
    from skimage.transform import rotate, resize

    # 添加噪声
    noisy_image = random_noise(watermarked_img, mode='s&p', amount=0.05)
    
    # 旋转图像
    rotated_image = rotate(watermarked_img, angle=30, mode='wrap')
    
    # 裁剪图像
    cropped_image = watermarked_img[50:-50, 50:-50]
    
    # 计算鲁棒性：对噪声、旋转、裁剪后的图像进行水印提取
    extracted_watermark_noisy = extract_watermark(noisy_image, original_S, U_w, Vt_w, alpha)
    extracted_watermark_rotated = extract_watermark(rotated_image, original_S, U_w, Vt_w, alpha)
    extracted_watermark_cropped = extract_watermark(cropped_image, original_S, U_w, Vt_w, alpha)

    # 计算提取水印的MSE（噪声、旋转、裁剪后的提取效果）
    mse_noisy = mse(watermark_img, extracted_watermark_noisy)
    mse_rotated = mse(watermark_img, extracted_watermark_rotated)
    mse_cropped = mse(watermark_img, extracted_watermark_cropped)

    print(f"MSE (Noisy image): {mse_noisy:.4f}")
    print(f"MSE (Rotated image): {mse_rotated:.4f}")
    print(f"MSE (Cropped image): {mse_cropped:.4f}")


# 加载图像
original_img = io.imread("carrier.jpg")
watermark_img = io.imread("watermark.jpg")

# 调整图像尺寸，使它们相同
target_shape = (min(original_img.shape[0], watermark_img.shape[0]),
                min(original_img.shape[1], watermark_img.shape[1]))
original_img_resized = resize_image(original_img, target_shape)
watermark_img_resized = resize_image(watermark_img, target_shape)

# 嵌入水印
alpha = 2  # 控制水印的强度，可以调节这个值来改变提取效果
watermarked_img, U_o, original_S, Vt_o, U_w, watermark_S, Vt_w = embed_watermark(original_img_resized, watermark_img_resized, alpha=alpha)

# 从带水印的图像中提取水印
extracted_watermark = extract_watermark(watermarked_img, original_S, U_w, Vt_w, alpha=alpha)

# 显示结果
display_images(original_img_resized, watermarked_img, extracted_watermark, watermark_img_resized)

# 计算指标
calculate_metrics(original_img_resized, watermarked_img, extracted_watermark, watermark_img_resized)

# 测试鲁棒性
test_robustness(watermarked_img, watermark_img_resized, alpha=alpha)