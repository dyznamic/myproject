import os
import cv2
import numpy as np
import pywt
from PIL import Image, ImageEnhance
from skimage.metrics import peak_signal_noise_ratio as sk_psnr
from skimage.metrics import structural_similarity as sk_ssim
import argparse
import pandas as pd


def to_gray(img):
    if img is None:
        return None
    if len(img.shape) == 3:
        return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return img

def normalize01(arr):
    mn, mx = arr.min(), arr.max()
    if mx - mn == 0:
        return np.zeros_like(arr)
    return (arr - mn) / (mx - mn)

def ncc(a, b):
    a = a.astype(np.float64).ravel()
    b = b.astype(np.float64).ravel()
    if a.std() == 0 or b.std() == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0,1])

# DWT+SVD 嵌入
def embed_watermark(cover_bgr, watermark_gray, alpha=0.05, wavelet='haar'):
    # 将宿主转 YCrCb 用 Y 通道嵌入
    ycrcb = cv2.cvtColor(cover_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float32)
    Y = ycrcb[:,:,0]

    # DWT on Y
    LL, (LH, HL, HH) = pywt.dwt2(Y, wavelet)

    # SVD on LL
    Uc, Sc, VcT = np.linalg.svd(LL, full_matrices=False)

    # 处理水印：缩放到 LL 尺寸
    wm_rs = cv2.resize(watermark_gray, (LL.shape[1], LL.shape[0]), interpolation=cv2.INTER_LINEAR)
    wm_norm = normalize01(wm_rs)

    # SVD on watermarked normalized
    Uw, Sw, VwT = np.linalg.svd(wm_norm, full_matrices=False)

    # 修改奇异值
    S_marked = Sc + alpha * Sw

    # 重构 LL'
    LL_marked = (Uc @ np.diag(S_marked) @ VcT)

    # IDWT 重构 Y'
    Y_marked = pywt.idwt2((LL_marked, (LH, HL, HH)), wavelet)
    Y_marked = np.clip(Y_marked, 0, 255).astype(np.uint8)

    # 合并回彩色
    ycrcb[:,:,0] = Y_marked
    watermarked_bgr = cv2.cvtColor(ycrcb.astype(np.uint8), cv2.COLOR_YCrCb2BGR)

    side_info = {
        'Uc': Uc, 'VcT': VcT, 'Sc_original': Sc,
        'Uw': Uw, 'VwT': VwT, 'Sw': Sw,
        'wavelet': wavelet, 'alpha': alpha,
        'LL_shape': LL.shape
    }
    return watermarked_bgr, side_info

# 提取
def extract_watermark(attacked_bgr, side_info):
    wavelet = side_info['wavelet']
    alpha = side_info['alpha']
    Uc = side_info['Uc']; VcT = side_info['VcT']; Sc_orig = side_info['Sc_original']
    Uw = side_info['Uw']; VwT = side_info['VwT']
    # 从 attacked 考虑 Y 通道
    attacked_ycrcb = cv2.cvtColor(attacked_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float32)
    Y_att = attacked_ycrcb[:,:,0]

    LL_att, (LH, HL, HH) = pywt.dwt2(Y_att, wavelet)
    U_att, S_att, V_attT = np.linalg.svd(LL_att, full_matrices=False)

    # 估计 Sw = (S_att - Sc_orig) / alpha
    Sw_est = (S_att - Sc_orig) / (alpha + 1e-12)

    # 重建水印近似
    # 处理 shape mismatch
    minlen = min(len(Sw_est), Uw.shape[0], VwT.shape[1])
    Sw_trim = Sw_est[:minlen]
    Uw_trim = Uw[:, :minlen]
    VwT_trim = VwT[:minlen, :]

    wm_rec = Uw_trim @ np.diag(Sw_trim) @ VwT_trim
    wm_norm = normalize01(wm_rec)
    wm_img = (wm_norm * 255).astype(np.uint8)
    # resize 回原始 watermark 大小
    return wm_img


def attack_flip(img):
    return cv2.flip(img, 1)

def attack_translate(img, tx=15, ty=10):
    h, w = img.shape[:2]
    M = np.float32([[1, 0, tx],[0, 1, ty]])
    return cv2.warpAffine(img, M, (w, h), borderMode=cv2.BORDER_REFLECT)

def attack_crop_resize(img, crop_frac=0.25):
    h, w = img.shape[:2]
    ch, cw = int(h*(1-crop_frac)), int(w*(1-crop_frac))
    y0 = (h - ch)//2; x0 = (w - cw)//2
    cropped = img[y0:y0+ch, x0:x0+cw]
    return cv2.resize(cropped, (w, h), interpolation=cv2.INTER_LINEAR)

def attack_contrast(img, factor=0.6):
    pil = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    enhancer = ImageEnhance.Contrast(pil)
    out = enhancer.enhance(factor)
    return cv2.cvtColor(np.array(out), cv2.COLOR_RGB2BGR)

def attack_jpeg(img, quality=40):
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
    _, enc = cv2.imencode('.jpg', img, encode_param)
    dec = cv2.imdecode(enc, cv2.IMREAD_UNCHANGED)
    return dec

def attack_blur(img, ksize=5):
    return cv2.GaussianBlur(img, (ksize, ksize), 0)

# 评估
def eval_metrics(original_cover, watermarked_img, extracted_wm, original_wm):
    metrics = {}
    # PSNR/SSIM on Y channel
    if original_cover.ndim == 3:
        oc_y = cv2.cvtColor(original_cover, cv2.COLOR_BGR2YCrCb)[:,:,0]
        wm_y = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YCrCb)[:,:,0]
    else:
        oc_y = original_cover
        wm_y = watermarked_img

    metrics['PSNR_cover'] = sk_psnr(oc_y, wm_y, data_range=255)
    metrics['SSIM_cover'] = sk_ssim(oc_y, wm_y, data_range=255)

    ew = extracted_wm
    ow = original_wm
    if ew.shape != ow.shape:
        ew = cv2.resize(ew, (ow.shape[1], ow.shape[0]), interpolation=cv2.INTER_LINEAR)
    metrics['NCC_wm'] = ncc(ow, ew)
    return metrics


def run_pipeline(cover_path, wm_path, alpha=0.05, out_dir='out_results'):
    os.makedirs(out_dir, exist_ok=True)
    cover = cv2.imread(cover_path)
    if cover is None:
        raise FileNotFoundError(f"cover not found: {cover_path}")
    wm_gray = cv2.imread(wm_path, cv2.IMREAD_GRAYSCALE)
    if wm_gray is None:
        raise FileNotFoundError(f"watermark not found: {wm_path}")

    watermarked, side = embed_watermark(cover, wm_gray, alpha=alpha)
    cv2.imwrite(os.path.join(out_dir, 'watermarked.png'), watermarked)


    # 攻击列表
    attacks = {
        'none': lambda x: x,
        'flip': attack_flip,
        'translate': lambda x: attack_translate(x, tx=20, ty=15),
        'crop25': lambda x: attack_crop_resize(x, crop_frac=0.25),
        'contrast50': lambda x: attack_contrast(x, factor=0.5),
        'jpeg40': lambda x: attack_jpeg(x, quality=40),
        'blur5': lambda x: attack_blur(x, ksize=5)
    }

    rows = []
    for name, fn in attacks.items():
        attacked = fn(watermarked.copy())
        attacked_path = os.path.join(out_dir, f'attacked_{name}.png')
        cv2.imwrite(attacked_path, attacked)

        extracted = extract_watermark(attacked, side)
        # 将提取结果 resize 回原始 watermark 大小以便对比
        extracted_resized = cv2.resize(extracted, (wm_gray.shape[1], wm_gray.shape[0]), interpolation=cv2.INTER_LINEAR)
        extracted_path = os.path.join(out_dir, f'extracted_{name}.png')
        cv2.imwrite(extracted_path, extracted_resized)

        metrics = eval_metrics(cover, attacked, extracted_resized, wm_gray)
        metrics_row = {'attack': name, 'PSNR_cover': metrics['PSNR_cover'], 'SSIM_cover': metrics['SSIM_cover'], 'NCC_wm': metrics['NCC_wm']}
        rows.append(metrics_row)
        print(f"[{name}] PSNR={metrics_row['PSNR_cover']:.2f}, SSIM={metrics_row['SSIM_cover']:.4f}, NCC={metrics_row['NCC_wm']:.4f}")

    df = pd.DataFrame(rows)
    csv_path = os.path.join(out_dir, 'results.csv')
    df.to_csv(csv_path, index=False)
    return out_dir, df


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('--cover', required=True, help='D:\pyproject\cover.jpg')
    p.add_argument('--wm', required=True, help='D:\pyproject\wm.png')
    p.add_argument('--alpha', type=float, default=0.05, help='embedding strength (0.01~0.2 typical)')
    p.add_argument('--out', default='out_results', help='D:\pyproject')
    args = p.parse_args()
    run_pipeline(args.cover, args.wm, alpha=args.alpha, out_dir=args.out)
