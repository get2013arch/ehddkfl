/* MalwareGuard — 프론트엔드 로직 */

// ── 탭 전환 ──────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

// ── 드래그 앤 드롭 / 파일·폴더 선택 ─────────────────────
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const folderInput = document.getElementById("folderInput");
const fileInfo = document.getElementById("fileInfo");
const scanBtn = document.getElementById("scanBtn");

let selectedFiles = [];   // 단일 파일 또는 폴더 내 파일 목록
let currentMode = "file"; // "file" | "folder"

function setMode(mode) {
  currentMode = mode;
  selectedFiles = [];
  fileInfo.classList.add("hidden");
  scanBtn.disabled = true;

  document.getElementById("modeFile").classList.toggle("active", mode === "file");
  document.getElementById("modeFolder").classList.toggle("active", mode === "folder");
  document.getElementById("dropIcon").textContent = mode === "folder" ? "📁" : "📄";
  document.getElementById("dropText").textContent =
    mode === "folder" ? "폴더를 여기에 드롭하거나 클릭하여 선택" : "파일을 여기에 드롭하거나 클릭하여 선택";
}

dropzone.addEventListener("click", () => {
  if (currentMode === "folder") folderInput.click();
  else fileInput.click();
});

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) handleFilesSelect([fileInput.files[0]]);
});
folderInput.addEventListener("change", () => {
  if (folderInput.files.length) handleFilesSelect(Array.from(folderInput.files));
});

dropzone.addEventListener("dragover", e => {
  e.preventDefault();
  dropzone.classList.add("drag-over");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-over"));
dropzone.addEventListener("drop", e => {
  e.preventDefault();
  dropzone.classList.remove("drag-over");
  const items = e.dataTransfer.items;
  // 폴더 드롭 감지
  if (items && items.length > 0 && items[0].webkitGetAsEntry?.()?.isDirectory) {
    collectFolderFiles(items[0].webkitGetAsEntry()).then(files => {
      if (files.length) handleFilesSelect(files);
    });
  } else {
    const files = Array.from(e.dataTransfer.files);
    if (files.length) handleFilesSelect(files);
  }
});

async function collectFolderFiles(entry) {
  const result = [];
  async function readDir(dirEntry) {
    const reader = dirEntry.createReader();
    const entries = await new Promise(res => reader.readEntries(res));
    for (const e of entries) {
      if (e.isFile) {
        const file = await new Promise(res => e.file(res));
        result.push(file);
      } else if (e.isDirectory) {
        await readDir(e);
      }
    }
  }
  await readDir(entry);
  return result;
}

function handleFilesSelect(files) {
  selectedFiles = files;
  const totalSize = files.reduce((s, f) => s + f.size, 0);
  if (files.length === 1) {
    fileInfo.innerHTML = `<strong>${files[0].name}</strong> &nbsp;·&nbsp; ${formatBytes(files[0].size)}`;
  } else {
    fileInfo.innerHTML = `<strong>${files[0].webkitRelativePath?.split("/")[0] || "선택된 파일"}</strong>
      &nbsp;·&nbsp; ${files.length}개 파일 &nbsp;·&nbsp; 합계 ${formatBytes(totalSize)}`;
  }
  fileInfo.classList.remove("hidden");
  scanBtn.disabled = false;
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(2) + " MB";
}

// ── 파일/폴더 검사 ───────────────────────────────────────
async function scanSelected() {
  if (!selectedFiles.length) return;
  scanBtn.disabled = true;

  const resultArea = document.getElementById("fileResult");
  resultArea.classList.remove("hidden");

  if (selectedFiles.length === 1) {
    await scanSingleFile(selectedFiles[0], resultArea);
  } else {
    await scanMultipleFiles(selectedFiles, resultArea);
  }

  scanBtn.disabled = false;
  scanBtn.textContent = "검사 시작";
}

async function scanSingleFile(file, resultArea) {
  scanBtn.textContent = "검사 중...";
  resultArea.innerHTML = `<div class="result-card" style="border-color:var(--border)">
    <div class="result-header">
      <div class="result-icon">⏳</div>
      <div><div class="result-title">분석 중...</div>
      <div class="result-subtitle">AI가 파일 특징을 분석하고 있습니다</div></div>
    </div>
  </div>`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const resp = await fetch("/api/scan/file", { method: "POST", body: formData });
    const data = await resp.json();
    resultArea.innerHTML = data.error
      ? `<div class="alert alert-danger">${data.error}</div>`
      : buildFileResult(data);
  } catch (e) {
    resultArea.innerHTML = `<div class="alert alert-danger">서버 오류: ${e.message}</div>`;
  }
}

async function scanMultipleFiles(files, resultArea) {
  const total = files.length;
  let done = 0;
  const results = [];

  resultArea.innerHTML = `
    <div class="card">
      <div id="multiProgress">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px">
          <span>폴더 검사 중...</span>
          <span id="multiCount">0 / ${total}</span>
        </div>
        <div class="progress-bar-wrap">
          <div class="progress-bar" id="multiBar" style="width:0%"></div>
        </div>
        <p id="multiCurrent" class="current-file" style="margin-top:6px"></p>
      </div>
    </div>`;

  for (const file of files) {
    document.getElementById("multiCurrent").textContent = file.name;
    const formData = new FormData();
    formData.append("file", file);

    try {
      const resp = await fetch("/api/scan/file", { method: "POST", body: formData });
      const data = await resp.json();
      if (!data.error) results.push(data);
    } catch (_) {}

    done++;
    const pct = Math.round(done / total * 100);
    document.getElementById("multiBar").style.width = pct + "%";
    document.getElementById("multiCount").textContent = `${done} / ${total}`;
    scanBtn.textContent = `검사 중... ${pct}%`;
  }

  renderMultiResults(results, total, resultArea);
}

function renderMultiResults(results, total, resultArea) {
  const threats = results.filter(r => r.is_malware);
  const safe = results.filter(r => !r.is_malware);

  const summaryClass = threats.length > 0 ? "malware" : "safe";
  const summaryIcon = threats.length > 0 ? "⚠️" : "✅";
  const summaryTitle = threats.length > 0
    ? `${threats.length}개 위협 발견`
    : "모든 파일 안전";
  const summarySub = `총 ${total}개 파일 검사 · 위협 ${threats.length}개 · 안전 ${safe.length}개`;

  const threatItems = threats.map(d => buildFileResult(d)).join("");

  resultArea.innerHTML = `
    <div class="result-card ${summaryClass}">
      <div class="result-header">
        <div class="result-icon">${summaryIcon}</div>
        <div>
          <div class="result-title">${summaryTitle}</div>
          <div class="result-subtitle">${summarySub}</div>
        </div>
      </div>
    </div>
    ${threatItems}
    ${safe.length > 0 ? `
    <details style="margin-top:8px">
      <summary style="cursor:pointer;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);
        border-radius:8px;font-size:.9rem;color:var(--text2)">
        안전한 파일 ${safe.length}개 보기
      </summary>
      <div style="margin-top:6px">${safe.map(d => buildFileResult(d)).join("")}</div>
    </details>` : ""}`;
}

function buildFileResult(d) {
  const isMalware = d.is_malware;
  const cls = isMalware ? "malware" : "safe";
  const icon = isMalware ? "⚠️" : "✅";
  const title = isMalware ? "악성 프로그램 감지됨" : "안전한 파일";
  const confPct = isMalware ? d.confidence * 100 : (1 - d.confidence) * 100;

  // 신뢰 구간 표시 (악성이면 악성 확률 CI, 정상이면 정상 확률 CI)
  const ciLow  = isMalware ? (d.confidence_low  * 100).toFixed(1) : ((1 - d.confidence_high) * 100).toFixed(1);
  const ciHigh = isMalware ? (d.confidence_high * 100).toFixed(1) : ((1 - d.confidence_low)  * 100).toFixed(1);
  const subtitle = isMalware
    ? `악성 확률 ${(d.confidence * 100).toFixed(1)}% (95% CI: ${ciLow}% ~ ${ciHigh}%) — 즉시 조치가 필요합니다`
    : `정상 확률 ${((1 - d.confidence) * 100).toFixed(1)}% (95% CI: ${ciLow}% ~ ${ciHigh}%) — 위협이 발견되지 않았습니다`;

  let familyHtml = "";
  if (isMalware && d.family_info) {
    const isKnown = d.is_known_family;
    const knownBadge = isKnown
      ? `<span style="color:var(--warn)">● 알려진 악성코드 종류</span>`
      : `<span style="color:var(--danger)">● 새로운(미등록) 악성코드로 추정</span>`;
    const dangerClass = {
      "매우 높음": "danger-very-high",
      "높음": "danger-high",
      "중간": "danger-medium",
      "낮음": "danger-low",
    }[d.family_info.danger] || "";

    // 상위 3개 패밀리 후보
    let topFamilyHtml = "";
    if (d.top_families && d.top_families.length > 1) {
      const rows = d.top_families.map((tf, idx) => {
        const barColor = idx === 0 ? "var(--danger)" : idx === 1 ? "var(--warn)" : "var(--text2)";
        return `
          <div style="margin-bottom:6px">
            <div style="display:flex;justify-content:space-between;font-size:.82rem;margin-bottom:2px">
              <span>${idx === 0 ? "1순위" : idx === 1 ? "2순위" : "3순위"} &nbsp;${tf.ko}</span>
              <span style="color:${barColor};font-weight:600">${(tf.confidence * 100).toFixed(1)}%</span>
            </div>
            <div style="background:var(--bg3);border-radius:4px;height:6px;overflow:hidden">
              <div style="height:100%;width:${(tf.confidence * 100).toFixed(1)}%;background:${barColor};border-radius:4px"></div>
            </div>
          </div>`;
      }).join("");
      topFamilyHtml = `
        <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border)">
          <div style="font-size:.8rem;color:var(--text2);margin-bottom:8px">패밀리 분류 후보 (MC 드롭아웃 기반)</div>
          ${rows}
        </div>`;
    }

    familyHtml = `
      <div class="family-box">
        <h3>
          ${d.family_info.ko}
          <span class="danger-badge ${dangerClass}">위험도: ${d.family_info.danger}</span>
        </h3>
        <p>${knownBadge}</p>
        <p style="margin-top:8px">${d.family_info.description}</p>
        <div class="action">🛡️ <strong>권고 조치:</strong> ${d.family_info.action}</div>
        ${topFamilyHtml}
      </div>`;
  }

  return `
    <div class="result-card ${cls}">
      <div class="result-header">
        <div class="result-icon">${icon}</div>
        <div>
          <div class="result-title">${title}</div>
          <div class="result-subtitle">${subtitle}</div>
        </div>
      </div>
      <div class="result-grid">
        <div class="result-field">
          <div class="field-label">파일명</div>
          <div class="field-value">${d.name}</div>
        </div>
        <div class="result-field">
          <div class="field-label">SHA-256</div>
          <div class="field-value" style="font-size:.75rem">${d.sha256 || "계산 실패"}</div>
        </div>
        <div class="result-field">
          <div class="field-label">파일 크기</div>
          <div class="field-value">${formatBytes(d.size)}</div>
        </div>
        <div class="result-field">
          <div class="field-label">해시 DB 일치</div>
          <div class="field-value" style="color:${d.known_hash ? 'var(--danger)' : 'var(--ok)'}">
            ${d.known_hash ? "일치 (알려진 악성코드)" : "없음"}
          </div>
        </div>
        <div class="result-field">
          <div class="field-label">탐지 신뢰도</div>
          <div class="field-value">${confPct.toFixed(1)}%</div>
          <div class="confidence-bar-wrap">
            <div class="confidence-bar ${isMalware ? 'danger' : 'safe'}"
                 style="width:${confPct}%"></div>
          </div>
        </div>
        <div class="result-field">
          <div class="field-label">검사 시각</div>
          <div class="field-value">${d.scan_time}</div>
        </div>
      </div>
      ${familyHtml}
    </div>`;
}

// ── 시스템 스캔 ───────────────────────────────────────────
let currentJobId = null;
let pollInterval = null;

async function startSystemScan() {
  const path = document.getElementById("scanPath").value.trim();
  if (!path) return;

  document.getElementById("systemProgress").classList.remove("hidden");
  document.getElementById("stopBtn").classList.remove("hidden");
  document.getElementById("systemResult").innerHTML = "";
  document.getElementById("progressText").textContent = "스캔 시작 중...";
  document.getElementById("currentFile").textContent = "";

  try {
    const resp = await fetch("/api/scan/system/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    const data = await resp.json();

    if (data.error) {
      alert(data.error);
      return;
    }

    currentJobId = data.job_id;
    pollInterval = setInterval(pollScanStatus, 2000);
  } catch (e) {
    alert("스캔 시작 실패: " + e.message);
  }
}

async function pollScanStatus() {
  if (!currentJobId) return;

  try {
    const resp = await fetch(`/api/scan/system/status/${currentJobId}`);
    const job = await resp.json();

    document.getElementById("progressText").textContent =
      `검사 중: ${job.scanned}개 파일 완료 · 위협 발견: ${job.threats.length}건`;
    document.getElementById("currentFile").textContent = job.current_file || "";

    if (job.status === "done" || job.status === "error") {
      clearInterval(pollInterval);
      pollInterval = null;
      document.getElementById("stopBtn").classList.add("hidden");
      renderSystemResults(job);
    }
  } catch (e) {
    console.error("폴링 오류:", e);
  }
}

function stopScan() {
  clearInterval(pollInterval);
  pollInterval = null;
  currentJobId = null;
  document.getElementById("stopBtn").classList.add("hidden");
  document.getElementById("progressText").textContent = "스캔이 중지되었습니다.";
}

function renderSystemResults(job) {
  const area = document.getElementById("systemResult");

  if (job.threats.length === 0) {
    area.innerHTML = `
      <div class="result-card safe">
        <div class="result-header">
          <div class="result-icon">✅</div>
          <div>
            <div class="result-title">위협이 발견되지 않았습니다</div>
            <div class="result-subtitle">검사한 ${job.scanned}개 파일 모두 안전합니다</div>
          </div>
        </div>
      </div>`;
    return;
  }

  const itemsHtml = job.threats.map(t => {
    const info = t.family_info || {};
    return `
      <div class="threat-item">
        <div class="threat-item-icon">⚠️</div>
        <div class="threat-item-body">
          <div class="threat-item-name">${t.name}</div>
          <div class="threat-item-path">${t.path}</div>
          <div class="threat-item-meta">
            <span class="meta-chip">${info.ko || t.family}</span>
            <span class="meta-chip">악성 확률 ${(t.confidence * 100).toFixed(0)}%
              ${t.confidence_low != null ? `(${(t.confidence_low*100).toFixed(0)}~${(t.confidence_high*100).toFixed(0)}%)` : ""}
            </span>
            <span class="meta-chip">${formatBytes(t.size)}</span>
            ${t.is_known_family ? '<span class="meta-chip" style="color:var(--warn)">알려진 종류</span>'
              : '<span class="meta-chip" style="color:var(--danger)">미등록 종류</span>'}
          </div>
        </div>
      </div>`;
  }).join("");

  area.innerHTML = `
    <div class="card">
      <div class="threats-header">
        <h3>탐지된 위협 목록</h3>
        <span class="threat-count">${job.threats.length}건 발견</span>
      </div>
      <p style="font-size:.85rem;color:var(--text2);margin-bottom:14px">
        총 ${job.scanned}개 파일 검사 완료 · ${job.started_at} ~ ${job.finished_at}
      </p>
      ${itemsHtml}
    </div>`;
}

// ── 모델 학습 ─────────────────────────────────────────────
async function trainModel() {
  const log = document.getElementById("trainLog");
  log.classList.remove("hidden");
  log.textContent = "[학습 시작] 모델 학습을 서버에 요청했습니다...\n";

  try {
    const resp = await fetch("/api/train", { method: "POST" });
    const data = await resp.json();
    log.textContent += data.message + "\n";
    log.textContent += "서버 콘솔에서 진행상황을 확인하세요.\n";
    log.textContent += "완료 후 '상태 확인' 버튼을 눌러주세요.\n";
  } catch (e) {
    log.textContent += `오류: ${e.message}\n`;
  }
}

async function checkModelStatus() {
  try {
    const resp = await fetch("/api/model/status");
    const data = await resp.json();

    const detDot = document.getElementById("detectorStatus");
    const famDot = document.getElementById("familyStatus");
    const badge = document.getElementById("modelBadge");

    detDot.className = "status-dot " + (data.detector_ready ? "ready" : "not-ready");
    famDot.className = "status-dot " + (data.family_classifier_ready ? "ready" : "not-ready");

    if (data.fully_ready) {
      badge.innerHTML = `<span class="badge badge-ok">● 모델 준비됨</span>`;
    } else {
      badge.innerHTML = `<span class="badge badge-warn">● 모델 미준비</span>`;
    }

    const log = document.getElementById("trainLog");
    log.classList.remove("hidden");
    log.textContent += `\n[상태] 탐지 모델: ${data.detector_ready ? "✓ 준비됨" : "✗ 없음"}\n`;
    log.textContent += `[상태] 패밀리 분류기: ${data.family_classifier_ready ? "✓ 준비됨" : "✗ 없음"}\n`;
  } catch (e) {
    alert("상태 확인 실패: " + e.message);
  }
}

// ── 드라이브 목록 로드 ─────────────────────────────────────
async function loadDrives() {
  try {
    const resp = await fetch("/api/drives");
    const data = await resp.json();
    const container = document.getElementById("driveButtons");
    if (!container) return;

    data.drives.forEach((drive, i) => {
      const btn = document.createElement("button");
      btn.className = "drive-btn" + (i === 0 ? " active" : "");
      btn.textContent = drive;
      btn.onclick = () => {
        document.querySelectorAll(".drive-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById("scanPath").value = drive;
      };
      container.appendChild(btn);
    });

    // 전체 드라이브 버튼
    if (data.drives.length > 1) {
      const allBtn = document.createElement("button");
      allBtn.className = "drive-btn";
      allBtn.textContent = "전체 드라이브";
      allBtn.onclick = () => {
        document.querySelectorAll(".drive-btn").forEach(b => b.classList.remove("active"));
        allBtn.classList.add("active");
        document.getElementById("scanPath").value = "ALL";
      };
      container.appendChild(allBtn);
    }
  } catch (e) {
    console.error("드라이브 목록 로드 실패:", e);
  }
}

// 페이지 로드 시 모델 상태 및 드라이브 목록 확인
checkModelStatus();
loadDrives();
