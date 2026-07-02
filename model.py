"""
딥러닝 기반 악성 프로그램 탐지 모델
잔차 연결 + MC 드롭아웃 불확실성 추정 + 온도 보정(Temperature Scaling)
커리큘럼 학습 (1:5 → 1:15 점진적 비율 증가) + 패밀리별 서브변형 + 다양한 정상 프로파일
"""

import os
import json
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib
from data_collector import FEATURE_DIM, MALWARE_FAMILY_MAP

MODEL_PATH = "models/malware_detector.pth"
SCALER_PATH = "models/scaler.pkl"
FAMILY_MODEL_PATH = "models/family_classifier.pth"
LABEL_MAP_PATH = "models/label_map.json"
TEMP_PATH = "models/temperature.json"

FAMILY_LABELS = [k for k in MALWARE_FAMILY_MAP if k != "benign"]
NUM_FAMILIES = len(FAMILY_LABELS)
MC_PASSES = 20  # MC 드롭아웃 추론 횟수 (불확실성 추정용)

# 커리큘럼 학습 단계: (목표 비율, 학습 에포크, 설명)
# 악성이 적은 실제 환경(1:15)에 점진적으로 적응
CURRICULUM_STAGES = [
    {"ratio":  5, "epochs": 15, "desc": "1단계: 1:5  (기초 패턴 학습)"},
    {"ratio":  7, "epochs": 12, "desc": "2단계: 1:7  (정상 다양성 증가)"},
    {"ratio": 10, "epochs": 12, "desc": "3단계: 1:10 (불균형 적응)"},
    {"ratio": 13, "epochs":  8, "desc": "4단계: 1:13 (실전 근접)"},
    {"ratio": 15, "epochs":  8, "desc": "5단계: 1:15 (실전 비율 최종화)"},
]

# 피처 인덱스 참조 (FEATURE_DIM = 23)
# 0:machine_type  1:num_sections  2:timestamp  3:characteristics
# 4:sizeof_code   5:sizeof_init_data  6:sizeof_uninit_data  7:entry_point
# 8:image_base    9:sizeof_image  10:sizeof_headers  11:subsystem
# 12:dll_characteristics  13:major_os_version  14:minor_os_version
# 15:mean_section_entropy  16:max_section_entropy  17:min_section_entropy
# 18:total_section_size  19:import_count  20:suspicious_import_count
# 21:file_size  22:file_entropy

# --------------------------------------------------------------------------
# 패밀리별 서브변형 프로파일 (3~4개 변형 × 10 패밀리 = 30+ 서브프로파일)
# 각 서브변형: mean(23차원), std(23차원), weight(샘플 비중)
# --------------------------------------------------------------------------
# 판별에 중요한 차원: 1(섹션수) 11(서브시스템) 15-17(엔트로피) 19-20(임포트) 21(크기) 22(파일엔트로피)
# 나머지는 mean=0, std=1 (정규화 후 덜 중요)

_B = [332, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 6, 0]  # 공통 앞부분 기본값
_Bs = [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1]   # 공통 앞부분 표준편차

FAMILY_SUBVARIANTS: dict[str, list[dict]] = {

    # ── 랜섬웨어 ────────────────────────────────────────────────────────────
    "ransomware": [
        # 1. 크립토-랜섬웨어 (WannaCry/Locky): 파일 전체 암호화, 최고 엔트로피
        {"weight": 0.40,
         "mean": _B + [7.8, 7.95, 6.5,  0,  40, 10, 500000, 7.85],
         "std":  _Bs + [0.25, 0.05, 0.6, 1,  15,  3, 200000, 0.15]},
        # 2. 기업형 타겟 랜섬웨어 (Ryuk/REvil): 정교, 네트워크 내부 횡이동
        {"weight": 0.35,
         "mean": _B + [7.2, 7.7, 5.8,  0,  58, 12, 850000, 7.30],
         "std":  _Bs + [0.30, 0.20, 0.8, 1,  20,  3, 300000, 0.25]},
        # 3. 화면-잠금 랜섬웨어: 암호화 없이 화면 차단, 낮은 엔트로피
        {"weight": 0.25,
         "mean": _B + [5.5, 6.5, 3.8,  0,  25,  6, 140000, 5.80],
         "std":  _Bs + [0.50, 0.50, 1.0, 1,  10,  2,  60000, 0.40]},
    ],

    # ── 트로이 목마 ──────────────────────────────────────────────────────────
    "trojan": [
        # 1. 뱅킹 트로이 (Emotet/TrickBot): 브라우저 후킹, 다수 임포트
        {"weight": 0.38,
         "mean": _B + [6.5, 7.1, 4.5,  0,  88,  9, 360000, 6.90],
         "std":  _Bs + [0.45, 0.40, 1.0, 1,  30,  3, 150000, 0.35]},
        # 2. 원격 접속 트로이 (RAT): 지속성, 네트워크 중심
        {"weight": 0.35,
         "mean": _B + [7.0, 7.4, 5.0,  0,  62,  8, 250000, 7.10],
         "std":  _Bs + [0.40, 0.35, 0.9, 1,  22,  3, 120000, 0.30]},
        # 3. 정보 탈취 트로이 (Stealer): 자격증명 수집, 훅 API 다수
        {"weight": 0.27,
         "mean": _B + [6.2, 6.9, 4.0,  0,  98, 10, 195000, 6.50],
         "std":  _Bs + [0.50, 0.45, 1.1, 1,  35,  3, 100000, 0.40]},
    ],

    # ── 웜 ──────────────────────────────────────────────────────────────────
    "worm": [
        # 1. 네트워크 전파 웜 (MS17-010 등): 익스플로잇 + 자가복제
        {"weight": 0.40,
         "mean": _B + [6.8, 7.3, 4.5,  0,  68,  8, 230000, 6.90],
         "std":  _Bs + [0.40, 0.35, 1.0, 1,  22,  3, 110000, 0.35]},
        # 2. 이메일 웜 (SMTP 기반): 첨부파일 전파, 낮은 엔트로피
        {"weight": 0.35,
         "mean": _B + [5.9, 6.7, 3.5,  0,  47,  6, 175000, 6.10],
         "std":  _Bs + [0.50, 0.50, 1.2, 1,  18,  2,  80000, 0.45]},
        # 3. USB/이동식 저장장치 웜: Autorun 악용, 소형 파일
        {"weight": 0.25,
         "mean": _B + [5.7, 6.4, 3.0,  0,  33,  5,  78000, 5.90],
         "std":  _Bs + [0.55, 0.55, 1.3, 1,  14,  2,  35000, 0.50]},
    ],

    # ── 스파이웨어 ───────────────────────────────────────────────────────────
    "spyware": [
        # 1. 키로거 (훅 기반): 낮은 엔트로피로 탐지 회피, 소형
        {"weight": 0.38,
         "mean": _B + [5.1, 6.1, 3.4,  0,  82,  6, 118000, 5.80],
         "std":  _Bs + [0.55, 0.50, 1.1, 1,  30,  2,  55000, 0.50]},
        # 2. 화면 캡처 스파이웨어: GDI API 다수, 보통 크기
        {"weight": 0.32,
         "mean": _B + [5.7, 6.4, 3.9,  0,  73,  5, 205000, 6.00],
         "std":  _Bs + [0.50, 0.45, 1.0, 1,  25,  2,  90000, 0.45]},
        # 3. 브라우저 스파이 (자격증명 탈취): 많은 임포트
        {"weight": 0.30,
         "mean": _B + [5.4, 6.2, 3.7,  0, 105,  7, 188000, 5.95],
         "std":  _Bs + [0.60, 0.55, 1.2, 1,  38,  3,  85000, 0.50]},
    ],

    # ── 애드웨어 ─────────────────────────────────────────────────────────────
    "adware": [
        # 1. 브라우저 하이재커 (툴바 설치): 대형 파일, 다수 임포트
        {"weight": 0.40,
         "mean": _B + [4.8, 5.8, 2.8,  0, 135,  3, 920000, 5.40],
         "std":  _Bs + [0.65, 0.60, 1.2, 1,  45,  2, 350000, 0.60]},
        # 2. 팝업 광고 프로그램: 윈도우 API 중심
        {"weight": 0.35,
         "mean": _B + [5.1, 6.0, 3.1,  0, 112,  4, 720000, 5.55],
         "std":  _Bs + [0.60, 0.60, 1.1, 1,  40,  2, 280000, 0.55]},
        # 3. 검색 리다이렉터: 레지스트리 조작, 소형
        {"weight": 0.25,
         "mean": _B + [4.5, 5.5, 2.5,  0,  92,  2, 490000, 5.20],
         "std":  _Bs + [0.70, 0.70, 1.4, 1,  35,  2, 200000, 0.65]},
    ],

    # ── 루트킷 ───────────────────────────────────────────────────────────────
    "rootkit": [
        # 1. 커널 루트킷 (드라이버): subsystem=1, 적은 임포트, 커널 API
        {"weight": 0.40,
         "mean": [332, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6, 0,
                  6.0, 7.0, 3.0, 0, 28, 11, 82000, 6.40],
         "std":  [  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
                  0.55, 0.40, 1.5, 1, 12,  3, 38000, 0.40]},
        # 2. 사용자 모드 루트킷 (DKOM): 메모리 조작, 중간 크기
        {"weight": 0.35,
         "mean": _B + [6.5, 7.2, 3.5,  0,  47,  9, 125000, 6.65],
         "std":  _Bs + [0.50, 0.40, 1.4, 1,  18,  3,  55000, 0.40]},
        # 3. 부트킷 (MBR/VBR): 매우 고엔트로피, 최소 임포트, 초소형
        {"weight": 0.25,
         "mean": [332, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6, 0,
                  7.3, 7.85, 5.2, 0, 12, 13, 28000, 7.50],
         "std":  [  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
                  0.35, 0.15, 1.2, 1,  6,  3, 12000, 0.30]},
    ],

    # ── 백도어 ───────────────────────────────────────────────────────────────
    "backdoor": [
        # 1. 역방향 셸 (Meterpreter 계열): 소형, 네트워크 API, 중간 엔트로피
        {"weight": 0.38,
         "mean": _B + [6.5, 7.2, 4.5,  0,  42,  9,  62000, 6.80],
         "std":  _Bs + [0.45, 0.40, 1.0, 1,  15,  3,  28000, 0.40]},
        # 2. HTTP C2 백도어: HTTP API, 인증서 위장
        {"weight": 0.32,
         "mean": _B + [6.8, 7.3, 4.8,  0,  57, 10,  95000, 6.95],
         "std":  _Bs + [0.40, 0.35, 0.9, 1,  20,  3,  42000, 0.35]},
        # 3. 지속성 백도어 (레지스트리 등록): 시작프로그램 등록, 권한상승
        {"weight": 0.30,
         "mean": _B + [6.4, 7.1, 4.0,  0,  68, 11, 135000, 6.70],
         "std":  _Bs + [0.50, 0.45, 1.1, 1,  25,  3,  60000, 0.45]},
    ],

    # ── 드로퍼 ───────────────────────────────────────────────────────────────
    "dropper": [
        # 1. 내장 페이로드 드로퍼 (Upatre 계열): 내부 압축 → 매우 높은 엔트로피
        {"weight": 0.38,
         "mean": _B + [7.5, 7.92, 5.0,  0,  14,  4, 720000, 7.60],
         "std":  _Bs + [0.30, 0.08, 1.2, 1,   6,  2, 250000, 0.25]},
        # 2. 다단계 드로퍼: 여러 섹션, 복잡한 구조
        {"weight": 0.35,
         "mean": _B + [7.2, 7.8, 4.5,  0,  27,  6, 540000, 7.35],
         "std":  _Bs + [0.35, 0.20, 1.5, 1,  10,  2, 200000, 0.30]},
        # 3. 메모리-전용 드로퍼 (파일리스): 파일 엔트로피 최고, 임포트 극소
        {"weight": 0.27,
         "mean": _B + [7.85, 7.98, 6.2,  0,   7,  3, 195000, 7.90],
         "std":  _Bs + [0.15, 0.02, 0.9, 1,   3,  1,  90000, 0.10]},
    ],

    # ── 다운로더 ─────────────────────────────────────────────────────────────
    "downloader": [
        # 1. HTTP 다운로더: WinINet/WinHTTP API, 소형
        {"weight": 0.38,
         "mean": _B + [5.5, 6.5, 3.5,  0,  52,  7,  52000, 5.90],
         "std":  _Bs + [0.55, 0.50, 1.2, 1,  18,  3,  22000, 0.50]},
        # 2. P2P/분산 다운로더: 다수 소켓 API, 중형
        {"weight": 0.35,
         "mean": _B + [6.0, 6.8, 4.0,  0,  63,  6, 125000, 6.15],
         "std":  _Bs + [0.50, 0.45, 1.1, 1,  22,  2,  55000, 0.45]},
        # 3. 암호화 채널 다운로더 (TLS 우회): 높은 엔트로피 + 네트워크
        {"weight": 0.27,
         "mean": _B + [6.5, 7.0, 4.5,  0,  42,  8,  68000, 6.50],
         "std":  _Bs + [0.45, 0.40, 1.0, 1,  16,  3,  30000, 0.40]},
    ],

    # ── 분류 불명 악성코드 ───────────────────────────────────────────────────
    "unknown_malware": [
        # 1. 일반형: 여러 패밀리 특징 혼합
        {"weight": 0.38,
         "mean": _B + [6.5, 7.2, 4.0,  0,  57,  7, 260000, 6.80],
         "std":  _Bs + [0.70, 0.55, 1.5, 1,  28,  4, 150000, 0.55]},
        # 2. 탐지 회피형 (정상처럼 위장): 낮은 엔트로피, 적은 의심 API
        {"weight": 0.35,
         "mean": _B + [4.7, 5.5, 3.4,  0,  37,  3, 148000, 5.10],
         "std":  _Bs + [0.65, 0.65, 1.3, 1,  22,  2,  90000, 0.60]},
        # 3. APT/지능형 지속 위협: 정교, 낮은 탐지 프로파일, 소수 의심 API
        {"weight": 0.27,
         "mean": _B + [6.3, 7.0, 3.8,  0,  52,  5, 310000, 6.60],
         "std":  _Bs + [0.55, 0.50, 1.2, 1,  25,  2, 160000, 0.50]},
    ],
}

# --------------------------------------------------------------------------
# 정상 프로그램 서브변형 (6가지 실제 카테고리)
# 설치 프로그램처럼 고엔트로피를 가진 정상 파일도 포함 → "어려운 음성 사례"
# --------------------------------------------------------------------------
BENIGN_SUBVARIANTS: list[dict] = [
    # 1. 시스템 유틸리티 (notepad, calc, svchost 등): 소형, 낮은 엔트로피
    {"weight": 0.20,
     "mean": _B + [3.8, 4.8, 2.3,  0,  18,  0,  45000, 4.20],
     "std":  _Bs + [0.50, 0.60, 1.0, 1,  10,  0,  20000, 0.45]},
    # 2. 게임/멀티미디어 (그래픽·오디오 API 다수): 대형 파일, 중간 엔트로피
    {"weight": 0.18,
     "mean": _B + [5.5, 6.5, 3.5,  0, 158,  1, 2100000, 5.50],
     "std":  _Bs + [0.55, 0.55, 1.1, 1,  55,  1,  700000, 0.50]},
    # 3. 업무용 소프트웨어 (Office, 편집기 등): 중형, 보통 엔트로피
    {"weight": 0.18,
     "mean": _B + [5.0, 6.0, 3.0,  0, 125,  0, 520000, 5.20],
     "std":  _Bs + [0.55, 0.60, 1.2, 1,  45,  0, 200000, 0.50]},
    # 4. 브라우저/네트워크 앱 (Chrome, Firefox 계열): 네트워크 API 풍부
    {"weight": 0.16,
     "mean": _B + [5.5, 6.4, 3.6,  0, 105,  1, 840000, 5.55],
     "std":  _Bs + [0.50, 0.55, 1.1, 1,  38,  1, 320000, 0.50]},
    # 5. 설치 프로그램/Setup (내부 압축 페이로드): 엔트로피 높음! → 어려운 음성 사례
    {"weight": 0.15,
     "mean": _B + [6.5, 7.5, 4.6,  0,  82,  1, 1580000, 6.60],
     "std":  _Bs + [0.55, 0.45, 1.0, 1,  35,  1,  550000, 0.55]},
    # 6. 보안 소프트웨어 (AV, 방화벽): 시스템 API 다수, 의심 API 소수
    {"weight": 0.13,
     "mean": _B + [5.8, 7.0, 4.0,  0,  93,  3, 310000, 5.85],
     "std":  _Bs + [0.50, 0.50, 1.1, 1,  35,  2, 130000, 0.50]},
]

# 표시용 한국어 이름 (기존 유지)
FAMILY_FEATURE_PROFILES = {
    fam: {
        "mean": FAMILY_SUBVARIANTS[fam][0]["mean"],
        "std":  FAMILY_SUBVARIANTS[fam][0]["std"],
    }
    for fam in FAMILY_LABELS
}

FAMILY_KO = {
    "ransomware":    "랜섬웨어",
    "trojan":        "트로이 목마",
    "worm":          "웜",
    "spyware":       "스파이웨어",
    "adware":        "애드웨어",
    "rootkit":       "루트킷",
    "backdoor":      "백도어",
    "dropper":       "드로퍼",
    "downloader":    "다운로더",
    "unknown_malware": "알 수 없는 악성 프로그램",
}


# ============================================================
#  PyTorch 모델 구조
# ============================================================

class MalwareDataset(Dataset):
    def __init__(self, X: np.ndarray, y: np.ndarray):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


class ResidualBlock(nn.Module):
    """잔차 연결 블록: 기울기 소실 방지 + 더 깊은 표현력"""

    def __init__(self, dim: int, dropout: float):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
        )
        self.act = nn.ReLU()

    def forward(self, x):
        return self.act(x + self.block(x))


class MalwareDetector(nn.Module):
    """이진 분류 모델 (잔차 연결): 악성(1) vs 정상(0)"""

    def __init__(self, input_dim: int = FEATURE_DIM, dropout: float = 0.3):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.res1 = ResidualBlock(256, dropout)
        self.res2 = ResidualBlock(256, dropout)
        self.head = nn.Sequential(
            nn.Linear(256, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(64, 2),
        )

    def forward(self, x):
        return self.head(self.res2(self.res1(self.stem(x))))


class FamilyClassifier(nn.Module):
    """다중 클래스 모델 (잔차 연결): 악성 프로그램 종류 분류"""

    def __init__(self, input_dim: int = FEATURE_DIM, num_classes: int = NUM_FAMILIES, dropout: float = 0.4):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.res1 = ResidualBlock(512, dropout)
        self.res2 = ResidualBlock(512, dropout)
        self.head = nn.Sequential(
            nn.Linear(512, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(128, num_classes),
        )

    def forward(self, x):
        return self.head(self.res2(self.res1(self.stem(x))))


def _enable_dropout(model: nn.Module):
    """BatchNorm은 eval 상태 유지, Dropout만 활성화 (MC 드롭아웃 추론용)"""
    model.eval()
    for m in model.modules():
        if isinstance(m, nn.Dropout):
            m.train()


# ============================================================
#  데이터 생성
# ============================================================

def _generate_from_subvariants(
    subvariants: list[dict],
    n_total: int,
    rng: np.random.Generator,
) -> np.ndarray:
    """
    서브변형 목록에서 weight 비율대로 n_total개 샘플을 생성합니다.
    각 샘플은 무작위로 섞여서 반환됩니다.
    """
    weights = np.array([sv["weight"] for sv in subvariants], dtype=float)
    weights /= weights.sum()  # 정규화
    counts = (weights * n_total).astype(int)
    counts[-1] = n_total - counts[:-1].sum()  # 나머지 마지막에 할당

    parts = []
    for sv, n in zip(subvariants, counts):
        if n <= 0:
            continue
        s = rng.normal(loc=sv["mean"], scale=sv["std"], size=(n, FEATURE_DIM)).astype(np.float32)
        # 엔트로피 [0,8] 클리핑
        s[:, 15:18] = np.clip(s[:, 15:18], 0.0, 8.0)
        s[:, 22]    = np.clip(s[:, 22],    0.0, 8.0)
        # 카운트·크기는 음수 불가
        s[:, 1]     = np.clip(s[:, 1],     1.0, None)  # 섹션 최소 1
        s[:, 19:22] = np.clip(s[:, 19:22], 0.0, None)
        parts.append(s)

    samples = np.vstack(parts)
    rng.shuffle(samples)  # 서브변형 순서 섞기
    return samples


def _add_obfuscated_variants(
    malware: np.ndarray,
    family_labels: np.ndarray,
    rng: np.random.Generator,
    ratio: float = 0.20,
) -> tuple[np.ndarray, np.ndarray]:
    """
    UPX/패커로 난독화된 악성코드 변형 추가.
    - 엔트로피 전반적으로 상승
    - 임포트 수 감소 (언패커 스텁만 노출)
    - 기존 레이블 유지 (같은 패밀리지만 패킹된 버전)
    """
    n_obf = max(1, int(len(malware) * ratio))
    idx = rng.choice(len(malware), n_obf, replace=False)
    obf = malware[idx].copy()

    # 엔트로피 부스트 (패킹으로 전 구역 고엔트로피화)
    delta_e = rng.normal(0.9, 0.25, (n_obf, 3)).astype(np.float32)
    obf[:, 15:18] = np.clip(obf[:, 15:18] + delta_e, 0.0, 8.0)
    obf[:, 22]    = np.clip(obf[:, 22] + rng.normal(0.7, 0.15, n_obf).astype(np.float32), 0.0, 8.0)

    # 임포트 숨김 (패커가 실제 임포트를 숨김)
    obf[:, 19] = np.clip(obf[:, 19] * 0.15, 0.0, None)
    obf[:, 20] = np.clip(obf[:, 20] * 0.08, 0.0, None)

    return (
        np.vstack([malware, obf]),
        np.concatenate([family_labels, family_labels[idx]]),
    )


def _add_evasion_variants(
    malware: np.ndarray,
    family_labels: np.ndarray,
    rng: np.random.Generator,
    ratio: float = 0.10,
) -> tuple[np.ndarray, np.ndarray]:
    """
    정상 프로그램을 모방하는 탐지 회피 악성코드 변형 추가.
    엔트로피와 의심 임포트를 낮춰 정상처럼 위장.
    """
    n_ev = max(1, int(len(malware) * ratio))
    idx = rng.choice(len(malware), n_ev, replace=False)
    ev = malware[idx].copy()

    # 엔트로피 하향 조정 (정상 범위로 낮춤)
    ev[:, 15:18] = np.clip(ev[:, 15:18] * 0.65 + 2.0, 0.0, 8.0)
    ev[:, 22]    = np.clip(ev[:, 22]    * 0.65 + 2.0, 0.0, 8.0)
    # 의심 임포트 감소
    ev[:, 20] = np.clip(ev[:, 20] * 0.3, 0.0, None)

    return (
        np.vstack([malware, ev]),
        np.concatenate([family_labels, family_labels[idx]]),
    )


def generate_synthetic_dataset(n_malware: int = 5000, ratio: float = 15.0) -> tuple:
    """
    패밀리별 서브변형 + 다양한 정상 프로파일 + 난독화/회피 변형을 포함한
    현실적인 합성 학습 데이터를 생성합니다.

    - 악성 10개 패밀리 × 3 서브변형 + 난독화(20%) + 탐지회피(10%)
    - 정상 6개 카테고리 (설치파일 등 어려운 음성 포함)
    - 최종 악성:정상 = 1:ratio (커리큘럼용 최대 비율)
    - 반환 배열은 완전 무작위 순서로 셔플

    반환:
        X: 전체 특징 행렬 (N, FEATURE_DIM)
        y: 이진 레이블 (N,)  0=정상 1=악성
        X_malware: 악성 샘플만 (M, FEATURE_DIM)
        y_family: 패밀리 레이블 (M,)
    """
    rng = np.random.default_rng(42)
    n_per_family = n_malware // NUM_FAMILIES

    # ── 악성 샘플 생성 ──────────────────────────────────────────────────────
    malware_parts: list[np.ndarray] = []
    family_label_parts: list[np.ndarray] = []

    for i, fam in enumerate(FAMILY_LABELS):
        n = n_per_family if i < NUM_FAMILIES - 1 else n_malware - sum(len(p) for p in malware_parts)
        sv_list = FAMILY_SUBVARIANTS[fam]
        samples = _generate_from_subvariants(sv_list, n, rng)
        malware_parts.append(samples)
        family_label_parts.append(np.full(len(samples), i, dtype=np.int64))

    malware_raw = np.vstack(malware_parts)
    family_labels_raw = np.concatenate(family_label_parts)

    # ── 난독화 변형 추가 (20%) ───────────────────────────────────────────────
    malware_aug, family_labels_aug = _add_obfuscated_variants(
        malware_raw, family_labels_raw, rng, ratio=0.20
    )
    # ── 탐지 회피 변형 추가 (10%) ────────────────────────────────────────────
    malware_final, family_labels_final = _add_evasion_variants(
        malware_aug, family_labels_aug, rng, ratio=0.10
    )

    # ── 정상 샘플 생성 ──────────────────────────────────────────────────────
    n_benign = int(len(malware_final) * ratio)
    benign_features = _generate_from_subvariants(BENIGN_SUBVARIANTS, n_benign, rng)

    # ── 합치기 + 완전 무작위 셔플 ───────────────────────────────────────────
    X_combined = np.vstack([malware_final, benign_features])
    y_combined = np.concatenate([
        np.ones(len(malware_final), dtype=np.int64),
        np.zeros(n_benign, dtype=np.int64),
    ])

    # 위치 패턴 제거: 완전 무작위 순서로 섞음
    perm = rng.permutation(len(X_combined))
    X_combined = X_combined[perm]
    y_combined = y_combined[perm]

    # 패밀리 분류기 학습용: 악성 샘플만 따로 섞어서 반환
    malware_perm = rng.permutation(len(malware_final))
    X_malware = malware_final[malware_perm]
    y_family  = family_labels_final[malware_perm]

    return X_combined, y_combined, X_malware, y_family


# ============================================================
#  학습
# ============================================================

def _make_curriculum_sampler(
    y: np.ndarray,
    target_ratio: float,
    actual_malware_count: int,
    actual_benign_count: int,
) -> WeightedRandomSampler:
    """
    목표 비율 1:target_ratio를 시뮬레이션하는 WeightedRandomSampler.
    실제 데이터는 1:actual_ratio이므로 악성 샘플을 과표집.
    배치 내 순서는 완전 무작위.
    """
    actual_ratio = actual_benign_count / actual_malware_count
    # 악성 샘플을 (actual_ratio / target_ratio)배 더 자주 샘플링
    oversample = actual_ratio / target_ratio
    sample_weights = np.where(y == 1, float(oversample), 1.0)
    # 전체 샘플 수를 데이터 크기의 1배로 설정 (에포크당 충분한 다양성)
    return WeightedRandomSampler(
        weights=torch.tensor(sample_weights, dtype=torch.float32),
        num_samples=len(sample_weights),
        replacement=True,
    )


def make_weighted_sampler(labels: np.ndarray) -> WeightedRandomSampler:
    """클래스 불균형을 보정하는 가중치 샘플러 생성 (1단계 호환용)"""
    class_counts = np.bincount(labels)
    weights = 1.0 / class_counts
    sample_weights = weights[labels]
    return WeightedRandomSampler(
        weights=torch.tensor(sample_weights, dtype=torch.float32),
        num_samples=len(sample_weights),
        replacement=True,
    )


def _calibrate_temperature(model: nn.Module, val_loader: DataLoader, device) -> float:
    """
    온도 보정(Temperature Scaling): 검증 세트 NLL을 최소화하는 온도 T를 찾아
    softmax 확률이 실제 정확도와 일치하도록 교정합니다.
    T > 1 이면 확률을 낮춰(덜 자신감 있게), T < 1 이면 높입니다.
    """
    temperature = nn.Parameter(torch.ones(1, device=device) * 1.5)
    optimizer = optim.LBFGS([temperature], lr=0.05, max_iter=100)
    criterion = nn.CrossEntropyLoss()

    logits_list, labels_list = [], []
    model.eval()
    with torch.no_grad():
        for xb, yb in val_loader:
            logits_list.append(model(xb.to(device)).cpu())
            labels_list.append(yb)
    all_logits = torch.cat(logits_list)
    all_labels = torch.cat(labels_list)

    def step():
        optimizer.zero_grad()
        scaled = all_logits.to(device) / temperature.clamp(min=0.1)
        loss = criterion(scaled, all_labels.to(device))
        loss.backward()
        return loss

    optimizer.step(step)
    t_val = float(temperature.item())
    os.makedirs("models", exist_ok=True)
    with open(TEMP_PATH, "w") as f:
        json.dump({"temperature": t_val}, f)
    print(f"[온도 보정] 최적 온도 T = {t_val:.3f}  (1.0 = 보정 없음, >1.0 = 확률 하향 조정)")
    return t_val


def train_detector(X_train, y_train, X_val, y_val, epochs: int = None, lr: float = 1e-3):
    """
    이진 분류 모델 커리큘럼 학습 + 온도 보정.

    커리큘럼 단계 (CURRICULUM_STAGES):
      1단계 1:5  → 2단계 1:7 → 3단계 1:10 → 4단계 1:13 → 5단계 1:15
    각 단계에서 WeightedRandomSampler + CrossEntropyLoss 가중치를 업데이트하여
    악성코드가 적은 실전 환경에 점진적으로 적응시킵니다.
    배치 구성은 매 에포크 완전 무작위 (위치 패턴 학습 방지).
    """
    os.makedirs("models", exist_ok=True)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)
    joblib.dump(scaler, SCALER_PATH)

    n_malware = int((y_train == 1).sum())
    n_benign  = int((y_train == 0).sum())
    actual_ratio = n_benign / n_malware

    val_ds     = MalwareDataset(X_val_s, y_val)
    val_loader = DataLoader(val_ds, batch_size=256, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model  = MalwareDetector().to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=10)

    best_val_loss = float("inf")
    total_epochs  = sum(s["epochs"] for s in CURRICULUM_STAGES)
    print(f"\n[커리큘럼 학습 시작] 장치: {device} | 총 에포크: {total_epochs}")
    print(f"  학습 세트 | 악성: {n_malware:,}개  정상: {n_benign:,}개  실제비율: 1:{actual_ratio:.1f}")

    global_epoch = 0

    for stage in CURRICULUM_STAGES:
        target_ratio = float(stage["ratio"])
        stage_epochs = stage["epochs"]
        print(f"\n  ▶ {stage['desc']}  ({stage_epochs}에포크)")

        # 이 단계의 샘플러: 악성 과표집으로 목표 비율 시뮬레이션
        sampler    = _make_curriculum_sampler(y_train, target_ratio, n_malware, n_benign)
        train_ds   = MalwareDataset(X_train_s, y_train)
        train_loader = DataLoader(train_ds, batch_size=256, sampler=sampler)

        # 손실 함수 가중치도 단계 비율에 맞춰 업데이트
        class_weights = torch.tensor([1.0, target_ratio], device=device)
        criterion = nn.CrossEntropyLoss(weight=class_weights)

        for epoch in range(1, stage_epochs + 1):
            global_epoch += 1
            model.train()
            train_loss = 0.0

            for xb, yb in train_loader:
                xb, yb = xb.to(device), yb.to(device)
                optimizer.zero_grad()
                loss = criterion(model(xb), yb)
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                train_loss += loss.item()

            scheduler.step()

            # 검증
            model.eval()
            val_loss = 0.0
            all_preds, all_labels = [], []
            with torch.no_grad():
                for xb, yb in val_loader:
                    xb, yb = xb.to(device), yb.to(device)
                    logits = model(xb)
                    val_loss += criterion(logits, yb).item()
                    all_preds.extend(logits.argmax(dim=1).cpu().numpy())
                    all_labels.extend(yb.cpu().numpy())

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                torch.save(model.state_dict(), MODEL_PATH)

            if epoch % 5 == 0 or epoch == stage_epochs:
                acc = np.mean(np.array(all_preds) == np.array(all_labels))
                print(f"    에포크 {global_epoch:3d} (단계내 {epoch:2d}) | "
                      f"학습손실: {train_loss/len(train_loader):.4f} | "
                      f"검증손실: {val_loss/len(val_loader):.4f} | "
                      f"정확도: {acc:.4f}")

    # 최적 가중치 불러온 후 온도 보정
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device, weights_only=True))
    _calibrate_temperature(model, val_loader, device)

    print(f"\n[커리큘럼 학습 완료] 최적 모델 저장 → {MODEL_PATH}")
    # 최종 검증 보고서
    model.eval()
    all_preds, all_labels = [], []
    final_criterion = nn.CrossEntropyLoss()
    with torch.no_grad():
        for xb, yb in val_loader:
            logits = model(xb.to(device))
            all_preds.extend(logits.argmax(dim=1).cpu().numpy())
            all_labels.extend(yb.cpu().numpy())
    print("\n[최종 검증 결과]")
    print(classification_report(all_labels, all_preds, target_names=["정상", "악성"]))
    return model


def train_family_classifier(X_malware, y_family, epochs: int = 60, lr: float = 1e-3):
    """
    악성 프로그램 패밀리 분류 모델 학습.
    증가된 학습 샘플에 맞춰 배치 크기·에포크 조정, 완전 무작위 셔플.
    """
    scaler = joblib.load(SCALER_PATH)
    X_s = scaler.transform(X_malware)

    n = len(X_s)
    idx = np.random.permutation(n)  # 완전 무작위 분할
    split = int(n * 0.8)
    train_idx, val_idx = idx[:split], idx[split:]

    train_ds = MalwareDataset(X_s[train_idx], y_family[train_idx])
    val_ds   = MalwareDataset(X_s[val_idx],   y_family[val_idx])
    # shuffle=True로 매 에포크 배치 순서 재무작위화
    train_loader = DataLoader(train_ds, batch_size=128, shuffle=True)
    val_loader   = DataLoader(val_ds,   batch_size=128, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model  = FamilyClassifier().to(device)

    # 패밀리별 균등 학습을 위한 가중치 (서브변형으로 이미 균형화됨)
    family_counts = np.bincount(y_family[train_idx], minlength=NUM_FAMILIES)
    family_weights = torch.tensor(
        1.0 / np.maximum(family_counts, 1), dtype=torch.float32, device=device
    )
    criterion = nn.CrossEntropyLoss(weight=family_weights)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=15)

    best_val_loss = float("inf")
    print(f"\n[패밀리 분류기 학습 시작]  클래스: {NUM_FAMILIES}종 | "
          f"학습: {len(train_idx):,}개 | 검증: {len(val_idx):,}개")

    for epoch in range(1, epochs + 1):
        model.train()
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

        scheduler.step()

        model.eval()
        val_loss = 0.0
        all_preds, all_labels = [], []
        with torch.no_grad():
            for xb, yb in val_loader:
                xb, yb = xb.to(device), yb.to(device)
                out = model(xb)
                val_loss += criterion(out, yb).item()
                all_preds.extend(out.argmax(dim=1).cpu().numpy())
                all_labels.extend(yb.cpu().numpy())

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), FAMILY_MODEL_PATH)

        if epoch % 10 == 0 or epoch == epochs:
            acc = np.mean(np.array(all_preds) == np.array(all_labels))
            print(f"  에포크 {epoch:3d} | 검증 손실: {val_loss/len(val_loader):.4f} | "
                  f"패밀리 정확도: {acc:.4f}")

    print(f"[패밀리 분류기 학습 완료] → {FAMILY_MODEL_PATH}")
    with open(LABEL_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(FAMILY_LABELS, f, ensure_ascii=False)

    # 최종 패밀리별 리포트
    model.load_state_dict(torch.load(FAMILY_MODEL_PATH, map_location=device, weights_only=True))
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for xb, yb in val_loader:
            out = model(xb.to(device))
            all_preds.extend(out.argmax(dim=1).cpu().numpy())
            all_labels.extend(yb.cpu().numpy())
    ko_names = [FAMILY_KO.get(FAMILY_LABELS[i], FAMILY_LABELS[i]) for i in range(NUM_FAMILIES)]
    print("\n[패밀리 분류 최종 결과]")
    print(classification_report(all_labels, all_preds, target_names=ko_names, zero_division=0))


# ============================================================
#  추론
# ============================================================

def load_models():
    """저장된 모델들을 불러옵니다."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    detector = MalwareDetector()
    detector.load_state_dict(torch.load(MODEL_PATH, map_location=device, weights_only=True))
    detector.to(device)
    detector.eval()

    family_clf = FamilyClassifier()
    family_clf.load_state_dict(torch.load(FAMILY_MODEL_PATH, map_location=device, weights_only=True))
    family_clf.to(device)
    family_clf.eval()

    scaler = joblib.load(SCALER_PATH)

    with open(LABEL_MAP_PATH, "r", encoding="utf-8") as f:
        family_labels = json.load(f)

    temperature = 1.0
    if os.path.exists(TEMP_PATH):
        with open(TEMP_PATH, "r") as f:
            temperature = json.load(f).get("temperature", 1.0)

    return detector, family_clf, scaler, family_labels, device, temperature


def predict(file_features: np.ndarray, models=None) -> dict:
    """
    특징 벡터를 받아 악성 여부와 패밀리를 예측합니다.

    MC 드롭아웃 20회 추론으로 불확실성을 추정하고,
    온도 보정으로 실제 정확도와 일치하는 현실적 확률을 반환합니다.

    반환:
        is_malware: 악성 여부
        confidence: 보정된 악성 확률 평균 (0~1)
        confidence_low: 95% 신뢰 구간 하한
        confidence_high: 95% 신뢰 구간 상한
        family: 1위 패밀리 이름
        family_confidence: 1위 패밀리 확률
        top_families: 상위 3개 패밀리 후보 목록
    """
    if models is None:
        models = load_models()

    detector, family_clf, scaler, family_labels, device, temperature = models

    X = scaler.transform(file_features.reshape(1, -1))
    x_tensor = torch.tensor(X, dtype=torch.float32).to(device)
    temp = max(float(temperature), 0.1)

    # MC 드롭아웃: 악성 탐지기
    _enable_dropout(detector)
    mc_det = []
    with torch.no_grad():
        for _ in range(MC_PASSES):
            logits = detector(x_tensor) / temp
            mc_det.append(torch.softmax(logits, dim=1).cpu().numpy()[0])
    detector.eval()

    mc_arr = np.array(mc_det)          # (MC_PASSES, 2)
    mean_p = mc_arr.mean(axis=0)
    std_p  = mc_arr.std(axis=0)

    malware_mean = float(mean_p[1])
    malware_std  = float(std_p[1])
    is_malware   = malware_mean > 0.5

    # 95% 신뢰 구간 (mean ± 1.96σ)
    ci_low  = float(np.clip(malware_mean - 1.96 * malware_std, 0.0, 1.0))
    ci_high = float(np.clip(malware_mean + 1.96 * malware_std, 0.0, 1.0))

    family = "N/A"
    family_confidence = 0.0
    top_families: list[dict] = []

    if is_malware:
        # MC 드롭아웃: 패밀리 분류기
        _enable_dropout(family_clf)
        mc_fam = []
        with torch.no_grad():
            for _ in range(MC_PASSES):
                fam_logits = family_clf(x_tensor)
                mc_fam.append(torch.softmax(fam_logits, dim=1).cpu().numpy()[0])
        family_clf.eval()

        fam_arr  = np.array(mc_fam)     # (MC_PASSES, NUM_FAMILIES)
        mean_fam = fam_arr.mean(axis=0)

        top3   = np.argsort(mean_fam)[::-1][:3]
        family = family_labels[int(top3[0])]
        family_confidence = float(mean_fam[top3[0]])

        top_families = [
            {
                "name":       family_labels[int(i)],
                "ko":         FAMILY_KO.get(family_labels[int(i)], family_labels[int(i)]),
                "confidence": round(float(mean_fam[i]), 4),
            }
            for i in top3
        ]

    return {
        "is_malware":        bool(is_malware),
        "confidence":        round(malware_mean, 4),
        "confidence_low":    round(ci_low, 4),
        "confidence_high":   round(ci_high, 4),
        "family":            family,
        "family_confidence": round(family_confidence, 4),
        "top_families":      top_families,
    }


if __name__ == "__main__":
    print("합성 데이터 생성 중 (서브변형 + 난독화 + 탐지회피, 악성:정상 = 1:15)...")
    X, y, X_malware, y_family = generate_synthetic_dataset(n_malware=5000)

    n = len(X)
    idx = np.random.permutation(n)
    split = int(n * 0.8)
    X_train, y_train = X[idx[:split]], y[idx[:split]]
    X_val,   y_val   = X[idx[split:]], y[idx[split:]]

    print(f"학습: {len(X_train):,}개 | 검증: {len(X_val):,}개")
    print(f"  악성: {y_train.sum():,}개 | 정상: {(y_train==0).sum():,}개")

    train_detector(X_train, y_train, X_val, y_val)
    train_family_classifier(X_malware, y_family, epochs=60)
    print("\n모든 모델 학습 완료!")
