import numpy as np
import matplotlib.pyplot as plt
from skimage import io, color
from skimage.transform import resize
from scipy.fftpack import dct, idct
from skimage.metrics import peak_signal_noise_ratio as psnr
from skimage.metrics import structural_similarity as ssim
from sklearn.metrics import mean_squared_error as mse

def resize_image(image, target_shape):
    resized_image = resize(image, target_shape, anti_aliasing=True)
    # 如果是RGB图像，则转换为灰度图像
    if resized_image.ndim == 3:  # 如果是RGB图像
        resized_image = color.rgb2gray(resized_image).astype(np.float64)
    return resized_image

def dct2(block):
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def idct2(block):
    return idct(idct(block.T, norm='ortho').T, norm='ortho')

def embed_watermark_dct(original_img, watermark_img, alpha=0.1):
    # 对原图进行分块处理（8x8 块）
    block_size = 8
    rows, cols = original_img.shape
    watermarked_img = np.copy(original_img)

    # 将水印图像缩放为与原图相同的大小
    watermark_img_resized = resize_image(watermark_img, (rows, cols))
    
    # 进行 DCT 嵌入
    for i in range(0, rows, block_size):
        for j in range(0, cols, block_size):
            block = original_img[i:i+block_size, j:j+block_size]
            watermark_block = watermark_img_resized[i:i+block_size, j:j+block_size]
            
            # 对每个 8x8 块进行 DCT 变换
            dct_block = dct2(block)
            
            # 嵌入水印（调整低频部分）
            dct_block[0, 0] += alpha * watermark_block[0, 0]
            
            # 逆 DCT 变换回图像
            watermarked_img[i:i+block_size, j:j+block_size] = idct2(dct_block)
    
    return watermarked_img

def extract_watermark_dct(watermarked_img, original_img, alpha=0.1):
    # 确保输入图像是灰度图像，如果不是，则转换为灰度图像
    if watermarked_img.ndim == 3:  # 如果是RGB图像
        watermarked_img = color.rgb2gray(watermarked_img).astype(np.float64)
    if original_img.ndim == 3:  # 如果是RGB图像
        original_img = color.rgb2gray(original_img).astype(np.float64)
    
    # 对原图进行分块处理（8x8 块）
    block_size = 8
    rows, cols = original_img.shape
    extracted_watermark = np.zeros_like(original_img)
    
    # 提取水印
    for i in range(0, rows, block_size):
        for j in range(0, cols, block_size):
            block = watermarked_img[i:i+block_size, j:j+block_size]
            original_block = original_img[i:i+block_size, j:j+block_size]
            
            # 对每个 8x8 块进行 DCT 变换
            dct_block_watermarked = dct2(block)
            dct_block_original = dct2(original_block)
            
            # 提取水印信息（从 DCT 系数中减去原图的低频部分）
            extracted_block = (dct_block_watermarked[0, 0] - dct_block_original[0, 0]) / alpha
            extracted_watermark[i:i+block_size, j:j+block_size] = extracted_block
    
    return extracted_watermark


def calculate_metrics(original_img, watermarked_img, extracted_watermark, watermark_img):
    # 调整图像尺寸确保一致性
    target_shape = (min(original_img.shape[0], watermarked_img.shape[0], extracted_watermark.shape[0]),
                    min(original_img.shape[1], watermarked_img.shape[1], extracted_watermark.shape[1]))
    
    # 调整所有图像的尺寸，确保图像为灰度图并且尺寸一致
    original_img_resized = resize_image(original_img, target_shape)
    watermarked_img_resized = resize_image(watermarked_img, target_shape)
    extracted_watermark_resized = resize_image(extracted_watermark, target_shape)
    watermark_img_resized = resize_image(watermark_img, target_shape)

    # 打印图像尺寸，确保一致性
    print(f"Original Image size: {original_img_resized.shape}")
    print(f"Watermarked Image size: {watermarked_img_resized.shape}")
    print(f"Extracted Watermark size: {extracted_watermark_resized.shape}")
    print(f"Watermark Image size: {watermark_img_resized.shape}")

    # 计算PSNR
    psnr_value = psnr(original_img_resized, watermarked_img_resized)
    print(f"PSNR between original and watermarked image: {psnr_value:.2f} dB")

    # 计算SSIM，需要显式指定 data_range 参数
    data_range = original_img_resized.max() - original_img_resized.min()
    ssim_value = ssim(original_img_resized, watermarked_img_resized, data_range=data_range)
    print(f"SSIM between original and watermarked image: {ssim_value:.4f}")
    
    # 计算MSE（水印提取的准确度）
    mse_value = mse(watermark_img_resized, extracted_watermark_resized)
    print(f"MSE between actual and extracted watermark: {mse_value:.4f}")
    
    # 计算提取水印与原始水印之间的相关系数（提取水印准确度）
    correlation_value = np.corrcoef(watermark_img_resized.flatten(), extracted_watermark_resized.flatten())[0, 1]
    print(f"Correlation between actual and extracted watermark: {correlation_value:.4f}")


# 加载图像
original_img = io.imread("carrier.jpg")
watermark_img = io.imread("watermark.jpg")

# 调整图像尺寸，使它们相同
target_shape = (min(original_img.shape[0], watermark_img.shape[0]),
                min(original_img.shape[1], watermark_img.shape[1]))
original_img_resized = resize_image(original_img, target_shape)
watermark_img_resized = resize_image(watermark_img, target_shape)

# 嵌入水印
alpha = 0.5  # 控制水印的强度
watermarked_img = embed_watermark_dct(original_img_resized, watermark_img_resized, alpha=alpha)

# 从带水印的图像中提取水印
extracted_watermark = extract_watermark_dct(watermarked_img, original_img_resized, alpha=alpha)

# 显示结果
plt.figure(figsize=(20, 10))

# 原始图像
plt.subplot(1, 4, 1)
plt.imshow(original_img_resized, cmap='gray')
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
plt.imshow(watermark_img_resized, cmap='gray')
plt.title("Actual Watermark")

plt.show()

# 计算指标
calculate_metrics(original_img_resized, watermarked_img, extracted_watermark, watermark_img_resized)
