"""
모델 학습 독립 실행 스크립트
python train.py 로 직접 실행하면 모델 학습 후 저장합니다.
"""

import numpy as np
from model import (
    generate_synthetic_dataset,
    train_detector,
    train_family_classifier,
    CURRICULUM_STAGES,
    NUM_FAMILIES,
    FAMILY_KO,
    FAMILY_LABELS,
)


def main():
    print("=" * 65)
    print("MalwareGuard 모델 학습")
    print("  · 잔차연결(ResidualBlock) + MC드롭아웃 + 온도보정")
    print("  · 패밀리별 3개 서브변형 (난독화·탐지회피 변형 포함)")
    print("  · 정상 프로그램 6개 카테고리 (설치파일 등 어려운 음성 포함)")
    print("  · 커리큘럼 학습: 1:5 → 1:7 → 1:10 → 1:13 → 1:15 점진 증가")
    print("  · 배치 완전 무작위 (위치 패턴 학습 방지)")
    print("=" * 65)

    # ── 데이터 생성 ──────────────────────────────────────────────────────
    print("\n[1/3] 합성 학습 데이터 생성 중...")
    print("  악성코드 종류:", ", ".join(FAMILY_KO.get(f, f) for f in FAMILY_LABELS))
    X, y, X_malware, y_family = generate_synthetic_dataset(n_malware=5000)

    malware_count = int(y.sum())
    benign_count  = int((y == 0).sum())
    print(f"  전체: {len(X):,}개 | 악성: {malware_count:,}개 | 정상: {benign_count:,}개")
    print(f"  실제 비율: 1:{benign_count / malware_count:.1f}")
    print(f"  악성 서브변형 수: {len(X_malware):,}개 (난독화·탐지회피 포함)")

    # 학습/검증 분리 (완전 무작위)
    n = len(X)
    idx = np.random.permutation(n)
    split = int(n * 0.8)
    X_train, y_train = X[idx[:split]], y[idx[:split]]
    X_val,   y_val   = X[idx[split:]], y[idx[split:]]
    print(f"  학습: {len(X_train):,}개 | 검증: {len(X_val):,}개")

    # ── 이진 탐지기 커리큘럼 학습 ────────────────────────────────────────
    total_epochs = sum(s["epochs"] for s in CURRICULUM_STAGES)
    print(f"\n[2/3] 이진 탐지 모델 커리큘럼 학습 (총 {total_epochs}에포크)")
    for s in CURRICULUM_STAGES:
        print(f"  {s['desc']} ({s['epochs']}에포크)")
    train_detector(X_train, y_train, X_val, y_val)

    # ── 패밀리 분류기 학습 ───────────────────────────────────────────────
    print(f"\n[3/3] 패밀리 분류 모델 학습 (60에포크, {NUM_FAMILIES}종)")
    train_family_classifier(X_malware, y_family, epochs=60)

    print("\n" + "=" * 65)
    print("학습 완료! 이제 python app.py 로 웹서버를 시작하세요.")
    print("=" * 65)


if __name__ == "__main__":
    main()
