"""Image security metrics for the research/evaluation layer (PRD sections 23-29).

    python evaluation/image_metrics.py photo.png [--save-dir evaluation/results] [--csv results.csv]

Runs the image through SecureLink's own AES-256-GCM (backend/app/security/crypto.py) and reports:
  Entropy      Shannon entropy of plaintext vs ciphertext bytes (max 8 bits/byte)
  MSE / PSNR   original vs decrypted pixels: recovery correctness (lossless -> MSE 0, PSNR infinite)
  Correlation  adjacent-pixel correlation (horizontal / vertical / diagonal), original vs cipher image
  NPCR / UACI  cipher images of the original and a one-pixel-modified copy

Interpretation caveats (see PLAN.md issues P2/P3):
  * AES-GCM is a stream (CTR-based) mode with a fresh random nonce per encryption. NPCR ~99.6 % and
    UACI ~33.4 % therefore reflect nonce freshness, not plaintext sensitivity of a custom image cipher.
  * The cipher "image" is the ciphertext body (nonce and 16-byte tag removed) reshaped to the image size.
  * SHA-256 equality already proves lossless recovery; MSE/PSNR are a sanity check.
"""
import argparse
import csv
import math
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app.security import crypto  # noqa: E402

AAD = b"evaluation-image"
KEY = bytes(range(32))  # fixed evaluation key, independent of the server's master key


def entropy(data: bytes) -> float:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def mse(a, b) -> float:
    return float(np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2))


def psnr(m: float) -> float:
    return math.inf if m == 0 else 10 * math.log10(255 ** 2 / m)


def correlation(img, direction, samples=10000, seed=0):
    """Correlation coefficient of randomly sampled adjacent pixel pairs (grayscale)."""
    gray = img.astype(np.float64).mean(axis=2)
    h, w = gray.shape
    dy, dx = {"horizontal": (0, 1), "vertical": (1, 0), "diagonal": (1, 1)}[direction]
    rng = np.random.default_rng(seed)
    ys = rng.integers(0, h - dy, samples)
    xs = rng.integers(0, w - dx, samples)
    x, y = gray[ys, xs], gray[ys + dy, xs + dx]
    if x.std() == 0 or y.std() == 0:
        return float("nan")
    return float(np.corrcoef(x, y)[0, 1])


def npcr_uaci(c1, c2):
    diff = c1 != c2
    npcr = diff.mean() * 100
    uaci = (np.abs(c1.astype(np.int16) - c2.astype(np.int16)) / 255).mean() * 100
    return float(npcr), float(uaci)


def encrypt_pixels(pixels):
    blob = crypto.encrypt(pixels.tobytes(), AAD, KEY)
    body = blob[crypto.NONCE_SIZE:-crypto.TAG_SIZE]  # same length as the plaintext
    return blob, np.frombuffer(body, dtype=np.uint8).reshape(pixels.shape)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image")
    parser.add_argument("--save-dir", help="write cipher/decrypted images here for the report")
    parser.add_argument("--csv", help="append results to this CSV file")
    args = parser.parse_args()

    raw_file = Path(args.image).read_bytes()
    original = np.array(Image.open(args.image).convert("RGB"), dtype=np.uint8)

    blob, cipher = encrypt_pixels(original)
    decrypted = np.frombuffer(crypto.decrypt(blob, AAD, KEY), dtype=np.uint8).reshape(original.shape)

    modified = original.copy()
    modified[0, 0, 0] = (int(modified[0, 0, 0]) + 1) % 256  # change one pixel by one level
    _, cipher2 = encrypt_pixels(modified)

    m = mse(original, decrypted)
    npcr, uaci = npcr_uaci(cipher, cipher2)
    file_blob = crypto.encrypt(raw_file, AAD, KEY)
    results = {
        "image": Path(args.image).name,
        "size": f"{original.shape[1]}x{original.shape[0]}",
        "entropy_original_pixels": entropy(original.tobytes()),
        "entropy_cipher_pixels": entropy(cipher.tobytes()),
        "entropy_original_file": entropy(raw_file),
        "entropy_encrypted_file": entropy(file_blob),
        "mse_original_vs_decrypted": m,
        "psnr_original_vs_decrypted": psnr(m),
        "sha256_match": crypto.sha256_hex(original.tobytes()) == crypto.sha256_hex(decrypted.tobytes()),
        **{f"corr_{d}_original": correlation(original, d) for d in ("horizontal", "vertical", "diagonal")},
        **{f"corr_{d}_cipher": correlation(cipher, d) for d in ("horizontal", "vertical", "diagonal")},
        "npcr_percent": npcr,
        "uaci_percent": uaci,
    }

    width = max(map(len, results))
    for k, v in results.items():
        shown = "inf (lossless)" if v == math.inf else (f"{v:.6f}" if isinstance(v, float) else v)
        print(f"{k:<{width}}  {shown}")
    print("\nIdeal reference: cipher entropy -> 8.0, cipher correlation -> 0, NPCR ~99.61 %, UACI ~33.46 %, "
          "MSE 0 / PSNR inf for decryption. See the caveats at the top of this script.")

    if args.save_dir:
        out = Path(args.save_dir)
        out.mkdir(parents=True, exist_ok=True)
        stem = Path(args.image).stem
        Image.fromarray(cipher).save(out / f"{stem}_cipher.png")
        Image.fromarray(decrypted).save(out / f"{stem}_decrypted.png")
        print(f"saved cipher/decrypted images to {out}")
    if args.csv:
        new = not Path(args.csv).exists()
        with open(args.csv, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results))
            if new:
                writer.writeheader()
            writer.writerow(results)


if __name__ == "__main__":
    main()
