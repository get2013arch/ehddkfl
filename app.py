"""
Flask 웹 애플리케이션 메인 서버
"""

import os
import sys
import json
import time
import threading
import uuid
from pathlib import Path
from flask import Flask, render_template, request, jsonify, stream_with_context, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 최대 100MB 업로드
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs("models", exist_ok=True)

# 전역 모델 인스턴스 (한 번만 로드)
_models = None
_models_lock = threading.Lock()
_known_hashes = None

# 진행 중인 스캔 상태 저장
_scan_jobs: dict[str, dict] = {}


def get_models():
    global _models, _known_hashes
    with _models_lock:
        if _models is None:
            try:
                from model import load_models
                _models = load_models()
                print("[앱] 모델 로드 완료")
            except Exception as e:
                print(f"[앱] 모델 로드 실패: {e}")
                return None, None
        if _known_hashes is None:
            from scanner import load_known_hashes
            _known_hashes = load_known_hashes()
    return _models, _known_hashes


def _enrich_result(result: dict) -> dict:
    """스캔 결과에 패밀리 상세 정보와 상위 후보 목록을 추가합니다."""
    if result.get("is_malware"):
        family_key = result.get("family", "unknown_malware")
        info = FAMILY_INFO.get(family_key, FAMILY_INFO["unknown_malware"])
        result["family_info"] = info
        result["is_known_family"] = family_key in FAMILY_INFO and family_key != "unknown_malware"
        # 상위 3개 패밀리 후보에도 상세 정보 첨부
        for tf in result.get("top_families", []):
            tf["info"] = FAMILY_INFO.get(tf["name"], FAMILY_INFO["unknown_malware"])
    else:
        result["family_info"] = None
        result["is_known_family"] = False
        result["top_families"] = []
    return result


FAMILY_INFO = {
    "ransomware": {
        "ko": "랜섬웨어",
        "description": "파일을 암호화하고 복호화 대가로 금전을 요구하는 악성 프로그램입니다.",
        "danger": "매우 높음",
        "action": "즉시 네트워크 차단 후 백업에서 복구하세요.",
    },
    "trojan": {
        "ko": "트로이 목마",
        "description": "정상 프로그램으로 위장하여 시스템에 침투하는 악성 프로그램입니다.",
        "danger": "높음",
        "action": "파일을 즉시 격리하고 시스템 전체 검사를 실시하세요.",
    },
    "worm": {
        "ko": "웜",
        "description": "네트워크를 통해 자가 복제하며 전파되는 악성 프로그램입니다.",
        "danger": "높음",
        "action": "네트워크를 차단하고 감염된 파일을 제거하세요.",
    },
    "spyware": {
        "ko": "스파이웨어",
        "description": "사용자 정보를 몰래 수집하여 외부로 전송하는 악성 프로그램입니다.",
        "danger": "중간",
        "action": "즉시 삭제하고 비밀번호를 변경하세요.",
    },
    "adware": {
        "ko": "애드웨어",
        "description": "무분별한 광고를 표시하거나 브라우저를 변조하는 프로그램입니다.",
        "danger": "낮음",
        "action": "파일을 삭제하고 브라우저 설정을 초기화하세요.",
    },
    "rootkit": {
        "ko": "루트킷",
        "description": "시스템 깊은 곳에 숨어 다른 악성 프로그램의 활동을 은폐합니다.",
        "danger": "매우 높음",
        "action": "OS 재설치를 권장합니다.",
    },
    "backdoor": {
        "ko": "백도어",
        "description": "공격자가 시스템에 원격으로 접근할 수 있는 통로를 만드는 악성 프로그램입니다.",
        "danger": "매우 높음",
        "action": "즉시 격리하고 시스템 접근 로그를 점검하세요.",
    },
    "dropper": {
        "ko": "드로퍼",
        "description": "다른 악성 프로그램을 시스템에 설치하는 역할을 하는 악성 프로그램입니다.",
        "danger": "높음",
        "action": "파일을 격리하고 추가 설치된 파일을 탐색하세요.",
    },
    "downloader": {
        "ko": "다운로더",
        "description": "인터넷에서 추가 악성 코드를 내려받아 실행하는 악성 프로그램입니다.",
        "danger": "높음",
        "action": "네트워크를 차단하고 파일을 즉시 삭제하세요.",
    },
    "unknown_malware": {
        "ko": "알 수 없는 악성 프로그램",
        "description": "아직 분류되지 않은 새로운 유형의 악성 프로그램으로 추정됩니다.",
        "danger": "알 수 없음",
        "action": "즉시 격리하고 보안 전문가에게 분석을 의뢰하세요.",
    },
}


@app.route("/")
def index():
    models, _ = get_models()
    model_ready = models is not None
    return render_template("index.html", model_ready=model_ready)


@app.route("/api/scan/file", methods=["POST"])
def scan_file_api():
    save_path = None
    try:
        if "file" not in request.files:
            return jsonify({"error": "파일이 없습니다."}), 400

        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "파일명이 없습니다."}), 400

        filename = secure_filename(f.filename)
        if not filename:
            filename = "uploaded_file"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        f.save(save_path)

        # 빈 파일 체크
        file_size = os.path.getsize(save_path)
        if file_size == 0:
            return jsonify({"error": "빈 파일입니다."}), 400

        models, known_hashes = get_models()
        if models is None:
            return jsonify({"error": "모델이 준비되지 않았습니다. 모델 관리 탭에서 학습을 먼저 실행하세요."}), 503

        from scanner import scan_file
        result = scan_file(save_path, models, known_hashes)
        # 업로드된 파일의 실제 크기를 반영
        result["size"] = file_size
        result["name"] = f.filename  # secure_filename 이전 원본 이름 사용

        result = _enrich_result(result)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"서버 오류: {str(e)}"}), 500
    finally:
        if save_path and os.path.exists(save_path):
            try:
                os.remove(save_path)
            except Exception:
                pass


@app.route("/api/scan/system/start", methods=["POST"])
def start_system_scan():
    import string as _string
    data = request.get_json(silent=True) or {}
    scan_path = data.get("path", "C:\\")

    # 전체 드라이브 스캔
    if scan_path.upper() == "ALL":
        scan_paths = [f"{d}:\\" for d in _string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    else:
        if not os.path.exists(scan_path):
            return jsonify({"error": f"경로가 존재하지 않습니다: {scan_path}"}), 400
        scan_paths = [scan_path]

    job_id = str(uuid.uuid4())
    _scan_jobs[job_id] = {
        "status": "running",
        "scanned": 0,
        "threats": [],
        "current_file": "",
        "scan_paths": scan_paths,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None,
    }

    def run_scan():
        from scanner import scan_directory
        models, known_hashes = get_models()
        if models is None:
            _scan_jobs[job_id]["status"] = "error"
            _scan_jobs[job_id]["error"] = "모델 로드 실패"
            return

        def on_progress(count, path):
            _scan_jobs[job_id]["scanned"] = count
            _scan_jobs[job_id]["current_file"] = path

        try:
            for sp in scan_paths:
                _scan_jobs[job_id]["current_file"] = f"[{sp}] 스캔 시작..."
                for result in scan_directory(sp, models, known_hashes, on_progress):
                    if result["is_malware"]:
                        _scan_jobs[job_id]["threats"].append(_enrich_result(result))
        except Exception as e:
            _scan_jobs[job_id]["error"] = str(e)
        finally:
            _scan_jobs[job_id]["status"] = "done"
            _scan_jobs[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()

    return jsonify({"job_id": job_id, "message": "스캔이 시작되었습니다."})


@app.route("/api/drives")
def list_drives():
    """사용 가능한 드라이브 목록 반환"""
    import string
    drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    return jsonify({"drives": drives})


@app.route("/api/scan/system/status/<job_id>")
def scan_status(job_id):
    job = _scan_jobs.get(job_id)
    if job is None:
        return jsonify({"error": "존재하지 않는 작업입니다."}), 404
    return jsonify(job)


@app.route("/api/train", methods=["POST"])
def train_model():
    """모델 학습 엔드포인트 (별도 스레드에서 실행)"""
    def do_train():
        import numpy as np
        from model import generate_synthetic_dataset, train_detector, train_family_classifier

        print("[학습] 데이터 생성 중...")
        X, y, X_malware, y_family = generate_synthetic_dataset(n_malware=2000)
        n = len(X)
        idx = np.random.permutation(n)
        split = int(n * 0.8)
        train_detector(X[idx[:split]], y[idx[:split]], X[idx[split:]], y[idx[split:]], epochs=60)
        train_family_classifier(X_malware, y_family, epochs=50)
        global _models
        _models = None  # 다음 요청 시 재로드

    t = threading.Thread(target=do_train, daemon=True)
    t.start()
    return jsonify({"message": "학습이 시작되었습니다. 완료까지 수 분이 소요됩니다."})


@app.route("/api/model/status")
def model_status():
    detector_exists = os.path.exists("models/malware_detector.pth")
    family_exists = os.path.exists("models/family_classifier.pth")
    return jsonify({
        "detector_ready": detector_exists,
        "family_classifier_ready": family_exists,
        "fully_ready": detector_exists and family_exists,
    })


if __name__ == "__main__":
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(debug=False, host="0.0.0.0", port=5000)
