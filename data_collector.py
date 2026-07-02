"""
악성 프로그램 정보 수집 모듈
MalwareBazaar, VirusTotal 공개 데이터셋 등에서 특징 정보를 수집합니다.
"""

import os
import json
import time
import hashlib
import requests
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional

# MalwareBazaar 무료 API (인증 불필요)
MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

MALWARE_FAMILY_MAP = {
    "ransomware": 0,
    "trojan": 1,
    "worm": 2,
    "spyware": 3,
    "adware": 4,
    "rootkit": 5,
    "backdoor": 6,
    "dropper": 7,
    "downloader": 8,
    "unknown_malware": 9,
    "benign": -1,
}

def fetch_malware_samples(limit: int = 100) -> list[dict]:
    """MalwareBazaar에서 최근 악성코드 샘플 메타데이터를 가져옵니다."""
    samples = []
    try:
        resp = requests.post(
            MALWARE_BAZAAR_API,
            data={"query": "get_recent", "selector": "time"},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                for item in data.get("data", [])[:limit]:
                    samples.append({
                        "sha256": item.get("sha256_hash", ""),
                        "family": item.get("tags", ["unknown_malware"])[0]
                                  if item.get("tags") else "unknown_malware",
                        "file_type": item.get("file_type", ""),
                        "file_size": item.get("file_size", 0),
                        "label": 1,  # 악성
                    })
    except Exception as e:
        print(f"[수집 오류] MalwareBazaar 연결 실패: {e}")
    return samples


NON_PE_ERRORS = {"DOS Header magic not found.", "Not a valid PE file."}

def extract_pe_features(file_path: str) -> Optional[dict]:
    """PE(Portable Executable) 파일에서 특징 벡터를 추출합니다."""
    try:
        import pefile
        pe = pefile.PE(file_path)

        features = {}

        # 헤더 특징
        features["machine_type"] = pe.FILE_HEADER.Machine
        features["num_sections"] = pe.FILE_HEADER.NumberOfSections
        features["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        features["characteristics"] = pe.FILE_HEADER.Characteristics
        features["sizeof_code"] = pe.OPTIONAL_HEADER.SizeOfCode
        features["sizeof_init_data"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features["sizeof_uninit_data"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features["image_base"] = pe.OPTIONAL_HEADER.ImageBase
        features["sizeof_image"] = pe.OPTIONAL_HEADER.SizeOfImage
        features["sizeof_headers"] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        features["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        features["major_os_version"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features["minor_os_version"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion

        # 섹션 특징
        section_entropies = []
        section_sizes = []
        for section in pe.sections:
            try:
                entropy = section.get_entropy()
                section_entropies.append(entropy)
                section_sizes.append(section.SizeOfRawData)
            except Exception:
                pass

        features["mean_section_entropy"] = float(np.mean(section_entropies)) if section_entropies else 0.0
        features["max_section_entropy"] = float(np.max(section_entropies)) if section_entropies else 0.0
        features["min_section_entropy"] = float(np.min(section_entropies)) if section_entropies else 0.0
        features["total_section_size"] = sum(section_sizes)

        # 임포트 특징
        import_count = 0
        suspicious_imports = {
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "SetWindowsHookEx", "RegSetValueEx", "WinExec", "ShellExecuteA",
            "URLDownloadToFile", "InternetOpenUrl", "CreateService",
            "OpenProcess", "AdjustTokenPrivileges", "NtUnmapViewOfSection",
        }
        suspicious_count = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="ignore")
                        if name in suspicious_imports:
                            suspicious_count += 1

        features["import_count"] = import_count
        features["suspicious_import_count"] = suspicious_count

        # 파일 크기 및 엔트로피
        with open(file_path, "rb") as f:
            raw = f.read()
        features["file_size"] = len(raw)
        features["file_entropy"] = _calculate_entropy(raw)

        pe.close()
        return features

    except PermissionError:
        return None  # 권한 없는 파일 조용히 건너뜀
    except Exception as e:
        msg = str(e)
        if not any(skip in msg for skip in NON_PE_ERRORS):
            # PE 형식이 아닌 파일(.msi, .bat 등)은 출력 생략
            print(f"[특징 추출 오류] {file_path}: {e}")
        return None


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    prob = freq / len(data)
    prob = prob[prob > 0]
    return float(-np.sum(prob * np.log2(prob)))


def features_to_vector(features: dict) -> np.ndarray:
    """특징 딕셔너리를 모델 입력 벡터로 변환합니다."""
    keys = [
        "machine_type", "num_sections", "timestamp", "characteristics",
        "sizeof_code", "sizeof_init_data", "sizeof_uninit_data", "entry_point",
        "image_base", "sizeof_image", "sizeof_headers", "subsystem",
        "dll_characteristics", "major_os_version", "minor_os_version",
        "mean_section_entropy", "max_section_entropy", "min_section_entropy",
        "total_section_size", "import_count", "suspicious_import_count",
        "file_size", "file_entropy",
    ]
    vec = [float(features.get(k, 0)) for k in keys]
    return np.array(vec, dtype=np.float32)


FEATURE_DIM = 23  # features_to_vector 출력 차원


def save_dataset(samples: list[dict], output_path: str = "dataset.json"):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)
    print(f"[저장] {len(samples)}개 샘플 → {output_path}")


def load_dataset(path: str = "dataset.json") -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    print("악성코드 샘플 메타데이터 수집 중...")
    samples = fetch_malware_samples(limit=50)
    print(f"수집된 샘플: {len(samples)}개")
    save_dataset(samples, "malware_meta.json")
