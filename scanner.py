"""
파일 및 시스템 스캔 모듈
사용자가 업로드한 파일 또는 컴퓨터 전체를 검사합니다.
"""

import os
import sys
import hashlib
import json
import time
from pathlib import Path
from typing import Generator
import numpy as np

from data_collector import extract_pe_features, features_to_vector, FEATURE_DIM

# 알려진 악성코드 해시 데이터베이스 (MalwareBazaar에서 수집된 sha256)
KNOWN_HASHES_PATH = "models/known_malware_hashes.json"

# PE 파싱이 가능한 실행 파일 확장자만 포함 (.msi .bat .vbs .js .ps1 등 스크립트/설치파일 제외)
SCAN_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".ocx", ".cpl"}

SYSTEM_SKIP_DIRS = {
    "windows\\winsxs", "windows\\servicing", "windows\\assembly",
    "$recycle.bin", "system volume information",
}

# 접근 불가 시스템 파일 (루트에 있는 특수 파일)
SKIP_FILENAMES = {"hiberfil.sys", "pagefile.sys", "swapfile.sys", "bootmgr"}


def compute_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except (PermissionError, OSError):
        return ""
    return h.hexdigest()


def load_known_hashes() -> set:
    if os.path.exists(KNOWN_HASHES_PATH):
        with open(KNOWN_HASHES_PATH, "r") as f:
            data = json.load(f)
        return set(data.get("hashes", []))
    return set()


def check_known_hash(sha256: str, known_hashes: set) -> bool:
    return sha256.lower() in known_hashes


def extract_features_safe(file_path: str) -> np.ndarray:
    """PE 파일 특징 추출, 실패 시 파일 크기/엔트로피 기반 기본 벡터 반환"""
    features = extract_pe_features(file_path)
    if features:
        return features_to_vector(features)

    # PE 파싱 실패 시 기본 통계 특징 사용
    vec = np.zeros(FEATURE_DIM, dtype=np.float32)
    try:
        with open(file_path, "rb") as f:
            raw = f.read(1024 * 1024)  # 최대 1MB 읽기
        freq = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
        prob = freq / len(raw)
        prob = prob[prob > 0]
        entropy = float(-np.sum(prob * np.log2(prob)))
        vec[22] = entropy  # file_entropy 슬롯
        vec[21] = float(os.path.getsize(file_path))  # file_size 슬롯
    except Exception:
        pass
    return vec


def scan_file(file_path: str, models=None, known_hashes: set = None) -> dict:
    """단일 파일 분석 결과 반환"""
    from model import predict, load_models

    if models is None:
        models = load_models()
    if known_hashes is None:
        known_hashes = load_known_hashes()

    path = Path(file_path)
    result = {
        "path": str(path.resolve()),
        "name": path.name,
        "size": 0,
        "sha256": "",
        "extension": path.suffix.lower(),
        "is_malware": False,
        "confidence": 0.0,
        "family": "N/A",
        "family_confidence": 0.0,
        "known_hash": False,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "error": None,
    }

    try:
        result["size"] = os.path.getsize(file_path)
        result["sha256"] = compute_sha256(file_path)
        result["known_hash"] = check_known_hash(result["sha256"], known_hashes)

        features = extract_features_safe(file_path)
        prediction = predict(features, models)
        result.update(prediction)

    except (PermissionError, OSError):
        result["error"] = "접근 권한 없음"
    except Exception as e:
        result["error"] = str(e)

    return result


def scan_directory(
    directory: str,
    models=None,
    known_hashes: set = None,
    progress_callback=None,
) -> Generator[dict, None, None]:
    """디렉토리 내 모든 대상 파일을 순차 스캔, 결과를 yield합니다."""
    from model import load_models

    if models is None:
        models = load_models()
    if known_hashes is None:
        known_hashes = load_known_hashes()

    total_scanned = 0
    for root, dirs, files in os.walk(directory, onerror=lambda e: None):
        root_lower = root.lower()
        if any(skip in root_lower for skip in SYSTEM_SKIP_DIRS):
            dirs.clear()
            continue

        for fname in files:
            if fname.lower() in SKIP_FILENAMES:
                continue
            ext = Path(fname).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue

            file_path = os.path.join(root, fname)
            result = scan_file(file_path, models, known_hashes)
            total_scanned += 1

            if progress_callback:
                progress_callback(total_scanned, file_path)

            yield result


def scan_system(models=None, known_hashes=None, progress_callback=None) -> Generator[dict, None, None]:
    """컴퓨터 전체 드라이브 스캔"""
    if sys.platform == "win32":
        import string
        drives = [
            f"{d}:\\"
            for d in string.ascii_uppercase
            if os.path.exists(f"{d}:\\")
        ]
    else:
        drives = ["/"]

    for drive in drives:
        yield from scan_directory(drive, models, known_hashes, progress_callback)
