document.addEventListener('DOMContentLoaded', function() {

    const DEBUG_MODE = false;
    const version = '3.0.1';
    // 상태 변수들
    let activeOperation = 'find-key';
    let selectedFolders = [];
    let isProcessing = false;
    let startTime = null;
    let endTime = null;
    let gameVersion = 'MV';
    let cleanFolders = true;
    let isScanning = false;

    // DOM 요소들
    const operationCards = document.querySelectorAll('.operation-card');
    const operationRadios = document.querySelectorAll('input[name="operation"]');
    const folderList = document.getElementById('folder-list');
    const encryptionKeyInput = document.getElementById('encryption-key');
    const mvButton = document.getElementById('mv-button');
    const mzButton = document.getElementById('mz-button');
    const startButton = document.getElementById('start-button');
    const refreshFoldersButton = document.getElementById('refresh-folders');
    const foundKeysContainer = document.getElementById('found-keys-container');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressPercentage = document.getElementById('progress-percentage');
    const currentFileContainer = document.getElementById('current-file-container');
    const currentFileSpan = document.getElementById('current-file');
    const logOutput = document.getElementById('log-output');
    const logSection = document.getElementById('log-section');
    const resultModal = document.getElementById('result-modal');
    const operationNameSpan = document.getElementById('operation-name');
    const totalFilesSpan = document.getElementById('total-files');
    const elapsedTimeSpan = document.getElementById('elapsed-time');
    const closeModalButton = document.getElementById('close-modal');
    const closeresultButton = document.getElementById('close-result-modal');
    const selectedCountSpan = document.getElementById('selected-count');

    // 로그 출력 섹션 표시
    if (logSection) {
        if (DEBUG_MODE) {
            logSection.classList.remove('hidden');
        } else {
            logSection.classList.add('hidden');
        }
    }

    // 로그 레벨 상수 정의
    const LOG_LEVELS = {
        DEBUG: { name: 'DEBUG', color: 'text-blue-400', show: true },
        INFO: { name: 'INFO', color: 'text-slate-300', show: true },
        WARN: { name: 'WARN', color: 'text-yellow-500', show: true },
        ERROR: { name: 'ERROR', color: 'text-red-500', show: true }
    };

    // 로그 설정
    const logConfig = {
        maxLogs: 500,               // 최대 로그 수 (오래된 것 자동 제거)
        timestamps: true,           // 타임스탬프 표시 여부
        logToConsole: DEBUG_MODE,   // DEBUG_MODE에 따라 콘솔 로그 출력 여부 결정
        minLevel: LOG_LEVELS.INFO,  // 최소 표시 로그 레벨
        expandDetails: false        // 상세 정보 확장 여부
    };

    // 향상된 로그 추가 함수
    function addLog(message, level = LOG_LEVELS.INFO, details = null) {
        // DEBUG_MODE가 false면 아무 로그도 남기지 않음 (성능 최적화)
        if (!DEBUG_MODE) return;

        // 로그 출력 영역이 없는 경우
        if (!logOutput) return;

        // 설정된 최소 레벨보다 낮은 로그는 표시하지 않음
        if (Object.values(LOG_LEVELS).indexOf(level) <
            Object.values(LOG_LEVELS).indexOf(logConfig.minLevel)) return;

        // 콘솔에도 출력
        if (logConfig.logToConsole) {
            const method = level === LOG_LEVELS.ERROR ? 'error' :
                        level === LOG_LEVELS.WARN ? 'warn' :
                        level === LOG_LEVELS.DEBUG ? 'debug' : 'log';
            console[method](`[${level.name}] ${message}`, details || '');
        }

        const logEntry = document.createElement('div');
        logEntry.className = `mb-1 ${level.color} log-entry`;

        // 타임스탬프 추가
        if (logConfig.timestamps) {
            const timeSpan = document.createElement('span');
            timeSpan.className = 'text-slate-400 mr-2';
            const now = new Date();
            const timeStr = `${now.toLocaleTimeString()}.${now.getMilliseconds().toString().padStart(3, '0')}`;
            timeSpan.textContent = `[${timeStr}]`;
            logEntry.appendChild(timeSpan);
        }

        // 로그 레벨 표시
        const levelSpan = document.createElement('span');
        levelSpan.className = `font-bold mr-2 ${level.color}`;
        levelSpan.textContent = `[${level.name}]`;
        logEntry.appendChild(levelSpan);

        // 메시지 추가
        logEntry.appendChild(document.createTextNode(message));

        // 상세 정보가 있는 경우 추가
        if (details) {
            const detailsButton = document.createElement('button');
            detailsButton.className = 'text-xs bg-slate-700 hover:bg-slate-600 px-1 ml-2 rounded';
            detailsButton.textContent = 'Details';

            const detailsDiv = document.createElement('div');
            detailsDiv.className = 'text-xs mt-1 pl-4 pb-1 text-slate-400 hidden';

            if (typeof details === 'object') {
                try {
                    detailsDiv.textContent = JSON.stringify(details, null, 2);
                } catch {
                    detailsDiv.textContent = String(details);
                }
            } else {
                detailsDiv.textContent = String(details);
            }

            detailsButton.addEventListener('click', () => {
                detailsDiv.classList.toggle('hidden');
            });

            logEntry.appendChild(detailsButton);
            logEntry.appendChild(detailsDiv);

            // 설정에 따라 상세 정보 자동 확장
            if (logConfig.expandDetails) {
                detailsDiv.classList.remove('hidden');
            }
        }

        // 첫 번째 로그 항목이면 기본 메시지 제거
        const defaultMessage = logOutput.querySelector('.text-center');
        if (defaultMessage) {
            logOutput.innerHTML = '';
        }

        logOutput.appendChild(logEntry);
        logOutput.scrollTop = logOutput.scrollHeight;

        // 최대 로그 개수 초과시 오래된 로그 제거
        const logs = logOutput.querySelectorAll('.log-entry');
        if (logs.length > logConfig.maxLogs) {
            for (let i = 0; i < logs.length - logConfig.maxLogs; i++) {
                logOutput.removeChild(logs[i]);
            }
        }
    }

    // 로그 초기화 함수 - DEBUG_MODE가 true일 때만 실행
    function initLogs() {
        // DEBUG_MODE가 false면 로그 시스템 초기화하지 않음
        if (!DEBUG_MODE) return;

        // 로그 출력 영역이 없는 경우
        if (!logOutput) return;

        // 로그 컨트롤 추가
        const logControls = document.createElement('div');
        logControls.className = 'flex justify-between items-center mb-2 p-2 bg-slate-700 rounded';

        // 레벨 필터 드롭다운
        const levelFilter = document.createElement('select');
        levelFilter.className = 'bg-slate-800 text-slate-300 rounded px-2 py-1 text-sm';
        Object.values(LOG_LEVELS).forEach(level => {
            const option = document.createElement('option');
            option.value = level.name;
            option.textContent = level.name;
            levelFilter.appendChild(option);
        });
        levelFilter.addEventListener('change', function() {
            logConfig.minLevel = LOG_LEVELS[this.value];
            // 모든 로그 항목 확인
            document.querySelectorAll('.log-entry').forEach(entry => {
                // 로그 레벨을 추출해서 비교
                const levelText = entry.querySelector('span:nth-child(2)').textContent;
                const entryLevel = Object.values(LOG_LEVELS).find(l =>
                    `[${l.name}]` === levelText
                );

                if (entryLevel &&
                    Object.values(LOG_LEVELS).indexOf(entryLevel) < Object.values(LOG_LEVELS).indexOf(logConfig.minLevel)) {
                    entry.classList.add('hidden');
                } else {
                    entry.classList.remove('hidden');
                }
            });
        });

        // 로그 내보내기 버튼
        const exportButton = document.createElement('button');
        exportButton.className = 'bg-blue-600 hover:bg-blue-500 text-white rounded px-2 py-1 text-sm';
        exportButton.textContent = 'Export Logs';
        exportButton.addEventListener('click', () => {
            // 모든 로그 텍스트 추출
            const logs = Array.from(document.querySelectorAll('.log-entry')).map(
                entry => entry.textContent
            ).join('\n');

            // 현재 날짜/시간을 파일명에 포함
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `app_logs_${timestamp}.txt`;

            // Python API를 통해 로그 파일 저장
            if (window.pywebview && window.pywebview.api) {
                window.pywebview.api.save_logs(logs, filename)
                    .then(result => {
                        if (result && result.success) {
                            logInfo(`로그가 저장되었습니다: ${result.path}`);
                        } else {
                            logError('로그 저장 실패');
                        }
                    })
                    .catch(error => {
                        logError(`로그 저장 중 오류 발생: ${error.message || error}`);
                    });
            } else {
                // Python API를 사용할 수 없는 경우 기존 방식으로 다운로드
                const blob = new Blob([logs], { type: 'text/plain' });
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = filename;
                a.click();
                URL.revokeObjectURL(a.href);
                logInfo('로그를 다운로드합니다. (Python API 사용 불가)');
            }
        });

        // 로그 지우기 버튼
        const clearButton = document.createElement('button');
        clearButton.className = 'bg-red-600 hover:bg-red-500 text-white rounded px-2 py-1 text-sm';
        clearButton.textContent = 'Delete Logs';
        clearButton.addEventListener('click', () => {
            logOutput.innerHTML = '';
            logInfo('로그가 지워졌습니다.');
        });

        // 컨트롤 요소 배치
        const filterGroup = document.createElement('div');
        filterGroup.className = 'flex items-center';
        const filterLabel = document.createElement('span');
        filterLabel.className = 'text-slate-300 mr-2 text-sm';
        filterLabel.textContent = 'Log Level:';
        filterGroup.appendChild(filterLabel);
        filterGroup.appendChild(levelFilter);

        logControls.appendChild(filterGroup);

        const buttonGroup = document.createElement('div');
        buttonGroup.className = 'flex gap-2';
        buttonGroup.appendChild(exportButton);
        buttonGroup.appendChild(clearButton);
        logControls.appendChild(buttonGroup);

        // 로그 섹션 시작 부분에 로그 컨트롤 추가
        logOutput.parentNode.insertBefore(logControls, logOutput);

        // 초기 로그 출력
        logInfo('로그 시스템이 초기화되었습니다.');
    }

    // DEBUG_MODE가 true일 때만 로그 시스템 초기화
    if (DEBUG_MODE) {
        initLogs();
    }

    // 로그 헬퍼 함수들
    function logDebug(message, details = null) {
        addLog(message, LOG_LEVELS.DEBUG, details);
    }

    function logInfo(message, details = null) {
        addLog(message, LOG_LEVELS.INFO, details);
    }

    function logWarn(message, details = null) {
        addLog(message, LOG_LEVELS.WARN, details);
    }

    function logError(message, details = null) {
        addLog(message, LOG_LEVELS.ERROR, details);
    }

    function initializeApplication() {
        //logInfo('애플리케이션 초기화 시작...');

        // 작업 선택 카드 초기화
        const findKeyCard = document.querySelector('#find-key-radio').closest('.operation-card');
        if (findKeyCard) {
            document.querySelectorAll('.operation-card').forEach(card => card.classList.remove('selected'));
            findKeyCard.classList.add('selected');
            document.getElementById('find-key-radio').checked = true;
        } else {
            logWarn('작업 선택 카드를 찾을 수 없습니다.');
        }

        // 폴더 추가 버튼 이벤트 연결
        if (addFolderButton) {
            addFolderButton.addEventListener('click', addCustomPath);
        }

        // 게임 버전 초기화
        if (mvButton && mzButton) {
            mvButton.classList.add('active');
            mzButton.classList.remove('active');
            gameVersion = 'MV';

            // 화살표 표시 초기화
            const rightArrow = mvButton.querySelector('.right-arrow');
            if (rightArrow) rightArrow.classList.remove('hidden');

            // z-index 초기화
            mvButton.style.zIndex = '2';
            mzButton.style.zIndex = '1';
        }

        initializeTooltips();
        initializeAddPathDropdown();

        //logInfo('애플리케이션 초기화 완료');
        logInfo('MVMZ-Crypter 준비 완료. 작업을 선택하고 시작하세요.');
        updateUIForOperation('find-key', true);
    }

    // 에러 케치 함수
    function catchError(fn, errorMessage = '작업 실행 중 오류 발생') {
        return function(...args) {
            try {
                return fn.apply(this, args);
            } catch (error) {
                logError(`${errorMessage}: ${error.message}`, {
                    stack: error.stack,
                    name: error.name,
                    function: fn.name,
                    arguments: args
                });
            }
        };
    }

    // 성능 관련 로그 함수
    function logPerformance(label, action) {
        const start = performance.now();
        let result;
        try {
            result = action();
        } catch (error) {
            logError(`${label} 실행 중 오류: ${error.message}`, error);
            throw error;
        } finally {
            const end = performance.now();
            logDebug(`${label} 실행 시간: ${(end - start).toFixed(2)}ms`);
        }
        return result;
    }

    function scanFolders() {
        if (isScanning) {
            logDebug("이미 스캔 중입니다. 중복 요청 무시");
            return;
        }

        isScanning = true;
        logInfo('폴더 스캔 준비 중...');
        showLoading();

        // Python API 호출
        if (window.pywebview && window.pywebview.api) {
            const source = activeOperation === 'decrypt' || activeOperation === 'find-key' || activeOperation === 'reencrypt' ? 'encrypted' : 'decrypted';
            logInfo(`${source} 폴더를 스캔합니다...`);

            window.pywebview.api.scan_folders(source)
                .then(result => {
                    hideLoading();
                    console.log("받은 결과:", result);

                    if (result && result.folders) {
                        updateFolderList(result.folders);
                        logInfo(`폴더 스캔 완료: ${result.folders.length}개 폴더/파일 찾음`);
                    } else {
                        logWarn('폴더를 찾을 수 없습니다');
                    }
                })
                .catch(error => {
                    hideLoading();
                    logError(`폴더 스캔 중 오류: ${error.message}`);
                })
                .finally(() => {
                    isScanning = false; // 스캔 상태 초기화
                });
        }
    }

    // 폴더 목록 업데이트
    function updateFolderList(folders) {
        if (!folderList) return;

        folderList.innerHTML = '';
        selectedFolders = [];

        folders.forEach(folder => {
            const folderItem = document.createElement('div');
            folderItem.className = 'flex items-center p-3 hover:bg-slate-700 border-b border-slate-700 cursor-pointer';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'mr-3';
            checkbox.checked = false; // 기본적으로 선택 해제

            // 파일 타입에 맞는 아이콘 가져오기
            const icon = document.createElement('span');
            icon.className = 'mr-2';
            icon.textContent = getFileIcon(folder);

            const folderName = document.createElement('span');
            folderName.className = 'text-slate-300';
            folderName.textContent = folder;

            // 체크박스와 아이콘, 폴더명을 항목에 추가
            folderItem.appendChild(checkbox);
            folderItem.appendChild(icon);
            folderItem.appendChild(folderName);

            // 체크박스 상태 변경 이벤트 핸들러
            function toggleCheckboxState() {
                checkbox.checked = !checkbox.checked;

                if (checkbox.checked) {
                    if (!selectedFolders.includes(folder)) {
                        selectedFolders.push(folder);
                    }
                } else {
                    const index = selectedFolders.indexOf(folder);
                    if (index > -1) {
                        selectedFolders.splice(index, 1);
                    }
                }
                updateSelectedCount();
            }

            // 폴더 항목 클릭 이벤트 - 체크박스 토글
            folderItem.addEventListener('click', function(e) {
                // 체크박스 자체를 클릭한 경우는 이벤트 중복 방지
                if (e.target !== checkbox) {
                    toggleCheckboxState();
                }
            });

            // 체크박스 자체 변경 이벤트 처리
            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    if (!selectedFolders.includes(folder)) {
                        selectedFolders.push(folder);
                    }
                } else {
                    const index = selectedFolders.indexOf(folder);
                    if (index > -1) {
                        selectedFolders.splice(index, 1);
                    }
                }
                updateSelectedCount();
            });

            folderList.appendChild(folderItem);
            if (checkbox.checked) {
                selectedFolders.push(folder);
            }
        });

        updateSelectedCount();
    }

    function getFileIcon(path) {
        // 파일 경로를 소문자로 변환하여 확장자 비교를 용이하게 함
        const lowercasePath = path.toLowerCase();

        // 이미지 파일 확인
        if (lowercasePath.endsWith('.rpgmvp') ||
            lowercasePath.endsWith('.png_') ||
            lowercasePath.endsWith('.png') ||
            lowercasePath.endsWith('.jpg') ||
            lowercasePath.endsWith('.jpeg') ||
            lowercasePath.endsWith('.gif')) {
          return '🖼️'; // 이미지 파일 아이콘
        }

        // 오디오 파일 확인
        else if (lowercasePath.endsWith('.rpgmvo') ||
                 lowercasePath.endsWith('.ogg_') ||
                 lowercasePath.endsWith('.rpgmvm') ||
                 lowercasePath.endsWith('.m4a_') ||
                 lowercasePath.endsWith('.mp3') ||
                 lowercasePath.endsWith('.wav') ||
                 lowercasePath.endsWith('.ogg')) {
          return '🎵'; // 음악 파일 아이콘
        }

        // JSON 파일 확인 (게임 데이터 파일)
        else if (lowercasePath.endsWith('.json')) {
          return '📜'; // 데이터 파일 아이콘
        }

        // JS 파일 확인
        else if (lowercasePath.endsWith('.js')) {
          return '📜'; // 스크립트 파일 아이콘
        }

        // 경로에 확장자가 없고 마지막에 '/'가 있거나 없으면 폴더로 간주
        else if (!path.includes('.') || path.endsWith('/')) {
          return '📁'; // 폴더 아이콘
        }

        // 기타 파일
        return '📄'; // 기본 파일 아이콘
      }

    // 선택된 폴더 개수 업데이트
    function updateSelectedCount() {
        if (selectedCountSpan) {
            selectedCountSpan.textContent = selectedFolders.length;
        }
    }

    // 작업 유형에 따른 UI 업데이트
    function updateUIForOperation(operation, forceUpdate = false, keepCustomPaths = false) {
        if (!forceUpdate && activeOperation === operation) return;

        activeOperation = operation;

        const keyInputArea = document.getElementById('key-input-area');
        const foundKeysContainer = document.getElementById('found-keys-container');
        const foundKeyswrapper = document.getElementById('key-container-wrapper');
        const gameVersionArea = document.getElementById('game-version-area');
        const dynamicSectionTitle = document.getElementById('dynamic-section-title');

        logInfo('UI 업데이트 시작', { operation });

        if (!keyInputArea || !gameVersionArea || !foundKeysContainer) {
            logWarn('필수 UI 요소를 찾을 수 없습니다. 재시도합니다.');
            setTimeout(() => updateUIForOperation(operation, true, keepCustomPaths), 100);
            return;
        }

        // 작업이 변경될 때마다 찾은 키 초기화
        if (foundKeysContainer) {
            foundKeysContainer.innerHTML = '<p class="text-gray-400 text-center" style="position: relative;top: 40px;">No keys found yet. Click Start to begin searching.</p>';
        }

        // 암호화 키 입력란도 초기화
        if (encryptionKeyInput) {
            encryptionKeyInput.value = '';
        }

        // 사용자 정의 경로 초기화 여부
        if (!keepCustomPaths) {
            logInfo('사용자 정의 경로가 초기화되었습니다.');
            customPathsMap.clear();
        } else {
            logInfo(`사용자 정의 경로가 유지됩니다. (${customPathsMap.size}개 경로)`);
        }

        switch(operation) {
            case 'find-key':
                keyInputArea.classList.add('hidden');
                foundKeysContainer.classList.remove('hidden');
                dynamicSectionTitle.classList.remove('hidden');
                foundKeyswrapper.classList.remove('hidden');
                if (dynamicSectionTitle) dynamicSectionTitle.textContent = 'Found Keys';
                gameVersionArea.classList.remove('hidden');
                gameVersionArea.classList.add('disabled-container');
                break;
            case 'decrypt':
                keyInputArea.classList.add('hidden');
                foundKeysContainer.classList.add('hidden');
                dynamicSectionTitle.classList.add('hidden');
                if (foundKeyswrapper) foundKeyswrapper.classList.add('hidden');
                gameVersionArea.classList.remove('hidden');
                gameVersionArea.classList.add('disabled-container');
                break;
            case 'encrypt':
            case 'reencrypt':
                // 암호화는 키 필수 - keyInputArea 항상 표시
                keyInputArea.classList.remove('hidden');
                foundKeysContainer.classList.add('hidden');
                dynamicSectionTitle.classList.remove('hidden');
                foundKeyswrapper.classList.remove('hidden');
                if (dynamicSectionTitle) dynamicSectionTitle.textContent = 'Encryption Key';
                gameVersionArea.classList.remove('hidden');
                gameVersionArea.classList.remove('disabled-container');
                break;
        }

        // 로딩 표시 후 지연시간을 두고 폴더 스캔 실행
        showLoading();
        setTimeout(() => {
            scanFolders();
        }, 200);
    }

    // 키 찾기 함수
    function findKey() {
        logInfo('암호화 키를 찾는 중...');

        if (window.pywebview && window.pywebview.api) {
            window.pywebview.api.find_encryption_key(selectedFolders)
                .then(result => {
                    // 성공 응답 처리는 operation-complete 이벤트에서 처리됨
                    if (!result || result.error) {
                        // 에러 응답만 여기서 처리
                        endProcessing(false);
                        logWarn(result?.error || '암호화 키를 찾을 수 없습니다');
                    }
                })
                .catch(error => {
                    endProcessing(false);
                    logError(`키 찾기 중 오류: ${error}`);
                });
        }
    }

    // 찾은 키 표시
    function displayFoundKeys(keys) {
        if (!foundKeysContainer) return;

        // 모든 키를 저장
        allFoundKeys = keys;
        totalKeyPages = Math.ceil(keys.length / keysPerPage);
        currentKeyPage = 1;

        const dynamicSectionTitle = document.getElementById('dynamic-section-title');
        if (dynamicSectionTitle) {
            dynamicSectionTitle.textContent = 'Found Keys';
        }

        // 컨테이너 표시
        foundKeysContainer.classList.remove('hidden');

        // key-input-area 숨기기
        const keyInputArea = document.getElementById('key-input-area');
        if (keyInputArea) {
            keyInputArea.classList.add('hidden');
        }

        // 페이지네이션된 키 표시
        displayPaginatedKeys();
    }

    // 페이지네이션 관련 상태 변수
    let currentKeyPage = 1;
    let keysPerPage = 1; // 페이지당 표시할 키 수
    let totalKeyPages = 1;
    let allFoundKeys = []; // 모든 찾은 키를 저장

    // 페이지네이션된 키 표시 함수
    function displayPaginatedKeys() {
        if (!foundKeysContainer) return;

        foundKeysContainer.innerHTML = '';

        // 현재 페이지에 표시할 키 계산
        const startIndex = (currentKeyPage - 1) * keysPerPage;
        const endIndex = Math.min(startIndex + keysPerPage, allFoundKeys.length);
        const currentPageKeys = allFoundKeys.slice(startIndex, endIndex);

        // 키가 없는 경우 메시지 표시
        if (allFoundKeys.length === 0) {
            foundKeysContainer.innerHTML = '<p class="text-gray-400 text-center">No keys found yet. Click Start to begin searching.</p>';
            return;
        }

        // 현재 페이지의 키 표시
        currentPageKeys.forEach(keyInfo => {
            const keyItem = document.createElement('div');
            keyItem.className = 'mb-3 p-3 bg-slate-700 rounded-md';

            const keyHeader = document.createElement('div');
            keyHeader.className = 'flex justify-between items-center mb-2';

            const keyValue = document.createElement('span');
            keyValue.className = 'font-mono text-blue-400';
            keyValue.textContent = keyInfo.key;

            const copyButton = document.createElement('button');
            copyButton.className = 'text-xs bg-slate-600 hover:bg-slate-500 px-2 py-1 rounded';
            copyButton.textContent = 'Copy';
            copyButton.onclick = (e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(keyInfo.key);
                copyButton.textContent = 'Copied!';
                setTimeout(() => { copyButton.textContent = 'Copy'; }, 1000);
            };

            keyHeader.appendChild(keyValue);
            const buttonGroup = document.createElement('div');
            buttonGroup.className = 'flex';
            buttonGroup.appendChild(copyButton);
            keyHeader.appendChild(buttonGroup);

            const foldersList = document.createElement('div');
            foldersList.className = 'text-xs text-slate-400';
            // 최대 표시할 폴더 수
            const maxFoldersToShow = 4;

            if (keyInfo.folders.length <= maxFoldersToShow) {
                // 폴더가 적으면 모두 표시
                foldersList.textContent = `${keyInfo.folders.join(', ')}`;
            } else {
                // 폴더가 많으면 일부만 표시하고 나머지는 +N개로 표시
                const shownFolders = keyInfo.folders.slice(0, maxFoldersToShow);
                const remainingCount = keyInfo.folders.length - maxFoldersToShow;
                foldersList.textContent = `${shownFolders.join(', ')} and ${remainingCount} more...`;

                // 툴팁으로 전체 폴더 목록을 볼 수 있게 설정
                foldersList.title = keyInfo.folders.join(', ');
                foldersList.style.cursor = 'help';

                // 클릭 시 전체 목록을 보여주는 토글 기능 추가
                let expanded = false;
                foldersList.addEventListener('click', () => {
                    if (expanded) {
                        foldersList.textContent = `${shownFolders.join(', ')} and ${remainingCount} more...`;
                    } else {
                        foldersList.textContent = keyInfo.folders.join(', ');
                    }
                    expanded = !expanded;
                });
            }

            keyItem.appendChild(keyHeader);
            keyItem.appendChild(foldersList);

            foundKeysContainer.appendChild(keyItem);
        });

        // 페이지 네비게이션 추가
        if (totalKeyPages > 1) {
            const paginationControls = document.createElement('div');
            paginationControls.className = 'flex justify-between items-center mt-3 pt-2 border-t border-slate-600';

            const pageInfo = document.createElement('span');
            pageInfo.className = 'text-xs text-slate-400';
            pageInfo.textContent = `${currentKeyPage}/${totalKeyPages} (Total ${allFoundKeys.length} keys)`;

            const buttonsContainer = document.createElement('div');
            buttonsContainer.className = 'flex space-x-2';

            // 이전 페이지 버튼
            const prevButton = document.createElement('button');
            prevButton.className = 'text-xs bg-slate-600 hover:bg-slate-500 px-2 py-1 rounded';
            prevButton.textContent = 'Prev';
            // 비활성화 코드 제거
            // prevButton.disabled = currentKeyPage === 1;
            // prevButton.style.opacity = currentKeyPage === 1 ? '0.5' : '1';
            prevButton.onclick = () => {
                if (currentKeyPage > 1) {
                    currentKeyPage--;
                } else {
                    // 첫 페이지에서 마지막 페이지로 순환
                    currentKeyPage = totalKeyPages;
                }
                displayPaginatedKeys();
            };

            // 다음 페이지 버튼 부분 수정
            const nextButton = document.createElement('button');
            nextButton.className = 'text-xs bg-slate-600 hover:bg-slate-500 px-2 py-1 rounded';
            nextButton.textContent = 'Next'; // 'next'를 'Next'로 변경 (일관성 유지)
            // 비활성화 코드 제거
            // nextButton.disabled = currentKeyPage === totalKeyPages;
            // nextButton.style.opacity = currentKeyPage === totalKeyPages ? '0.5' : '1';
            nextButton.onclick = () => {
                if (currentKeyPage < totalKeyPages) {
                    currentKeyPage++;
                } else {
                    // 마지막 페이지에서 첫 페이지로 순환
                    currentKeyPage = 1;
                }
                displayPaginatedKeys();
            };

            buttonsContainer.appendChild(prevButton);
            buttonsContainer.appendChild(nextButton);

            paginationControls.appendChild(pageInfo);
            paginationControls.appendChild(buttonsContainer);

            foundKeysContainer.appendChild(paginationControls);
        }
    }

    // 작업 시작 함수
    function startOperation() {
        logDebug('원본 startOperation 함수 실행됨');
        if (isProcessing || selectedFolders.length === 0) {
            logInfo('선택된 폴더가 없습니다');
            return;
        }
        // 선택된 폴더가 있는지 한 번 더 확인
        if (!selectedFolders || selectedFolders.length === 0) {
            logInfo('선택된 폴더가 없습니다. 폴더를 먼저 선택해주세요.');
            return;
        }
        const key = encryptionKeyInput ? encryptionKeyInput.value : '';

        // 암호화 작업인 경우에만 키 필수 체크
        if ((activeOperation === 'encrypt' || activeOperation === 'reencrypt') && !key) {
            logInfo('암호화 작업에는 암호화 키가 필요합니다');
            return;
        }

        startProcessing();

        // 경로 매핑 확인
        logDebug('경로 매핑 정보 확인:', Array.from(customPathsMap.entries()));

        // 경로 매핑 처리 후 작업 실행
        processPathMappingsAndExecute();
    }

    function processPathMappingsAndExecute() {
        if (customPathsMap.size > 0 && window.pywebview && window.pywebview.api) {
            logInfo('사용자 정의 경로 처리 중...');

            const pathMappings = {};
            for (const [displayName, pathData] of customPathsMap.entries()) {
                pathMappings[displayName] = {
                    originalPath: pathData.originalPath,
                    type: pathData.type
                };
            }

            // 작업 유형에 따른 결과 경로 표식 결정
            let pathSuffix = '';
            switch (activeOperation) {
                case 'decrypt': pathSuffix = '_decrypted'; break;
                case 'encrypt': pathSuffix = '_encrypted'; break;
                case 'reencrypt': pathSuffix = '_reencrypted'; break;
            }

            logInfo(`경로 매핑 정보 설정: ${Object.keys(pathMappings).length}개 항목, 접미사: ${pathSuffix}`);

            // 경로 매핑 정보 저장
            window.pywebview.api.set_path_mappings(pathMappings, pathSuffix)
                .then(result => {
                    if (result && result.success) {
                        logInfo('경로 매핑 정보가 저장되었습니다.');
                        executeOperation();
                    } else {
                        logError(`경로 매핑 저장 실패: ${result.error || '알 수 없는 오류'}`);
                        executeOperation();
                    }
                })
                .catch(error => {
                    logError(`경로 매핑 저장 중 오류: ${error.message || error}`);
                    executeOperation();
                });
        } else {
            logInfo('사용자 정의 경로가 없습니다. 기본 작업을 실행합니다.');
            executeOperation();
        }
    }

    // 실제 작업 실행 함수
    function executeOperation() {
        logDebug(`작업 실행: ${activeOperation}`);

        switch (activeOperation) {
            case 'find-key':
                findKey();
                break;
            case 'decrypt':
                decryptFiles(selectedFolders, encryptionKeyInput ? encryptionKeyInput.value : '');
                break;
            case 'encrypt':
                encryptFiles(selectedFolders, encryptionKeyInput ? encryptionKeyInput.value : '', gameVersion);
                break;
            case 'reencrypt':
                reencryptFiles(selectedFolders, encryptionKeyInput ? encryptionKeyInput.value : '', gameVersion);
                break;
        }
    }

    // 복호화 함수
    function decryptFiles(folders, key) {
        logInfo('복호화 작업을 시작합니다...');

        // 항상 새로운 키를 찾기 위해 기존에 찾은 키 정보를 초기화
        if (foundKeysContainer) {
            foundKeysContainer.innerHTML = '';
        }

        if (window.pywebview && window.pywebview.api) {
            window.pywebview.api.decrypt_files(folders, key, cleanFolders)
                .then(result => {
                    // 성공 응답 처리는 operation-complete 이벤트에서 처리됨
                    if (!result || result.error) {
                        endProcessing(false);
                        logError(result?.error || '복호화 중 오류 발생');
                    }
                })
                .catch(error => {
                    endProcessing(false);
                    logError(`복호화 중 오류: ${error}`);
                });
        }
    }

    // 암호화 함수
    function encryptFiles(folders, key, gameVersion) {
        logInfo('암호화 작업을 시작합니다...');

        // Python API 호출
        if (window.pywebview && window.pywebview.api) {
            window.pywebview.api.encrypt_files(folders, key, gameVersion, cleanFolders)
                .then(result => {
                    // 성공 응답 처리는 operation-complete 이벤트에서 처리됨
                    if (!result || result.error) {
                        endProcessing(false);
                        logError(result?.error || '암호화 중 오류 발생');
                    }
                })
                .catch(error => {
                    endProcessing(false);
                    logError(`암호화 중 오류: ${error}`);
                });
        }
    }

    // 재암호화 함수
    function reencryptFiles(folders, key, gameVersion) {
        logInfo('재암호화 작업을 시작합니다...');

        // Python API 호출
        if (window.pywebview && window.pywebview.api) {
            window.pywebview.api.reencrypt_files(folders, key, gameVersion, cleanFolders)
                .then(result => {
                    // 성공 응답 처리는 operation-complete 이벤트에서 처리됨
                    if (!result || result.error) {
                        endProcessing(false);
                        logError(result?.error || '재암호화 중 오류 발생');
                    }
                })
                .catch(error => {
                    endProcessing(false);
                    logError(`재암호화 중 오류: ${error}`);
                });
        }
    }

    // 처리 시작 함수
    function startProcessing() {
        isProcessing = true;
        startTime = new Date();
        endTime = null;

        // 작업 유형에 맞는 메시지로 로딩 인디케이터 표시
        const operationMessages = {
            'find-key': 'Finding Encryption Keys...',
            'decrypt': 'Decrypting Files...',
            'encrypt': 'Encrypting Files...',
            'reencrypt': 'Re-encrypting Files...'
        };
        showLoading(operationMessages[activeOperation] || '처리 중...');

        // 기존 코드 유지...
        const foundKeyswrapper = document.getElementById('key-container-wrapper');
        const foundKeysContainer = document.getElementById('found-keys-container');
        const keyInputArea = document.getElementById('key-input-area');
        const dynamicSectionTitle = document.getElementById('dynamic-section-title');

        // 모든 컨테이너 숨기기
        if (foundKeyswrapper) {
            foundKeyswrapper.classList.add('hidden');
        }

        if (foundKeysContainer) {
            foundKeysContainer.classList.add('hidden');
        }

        if (keyInputArea) {
            keyInputArea.classList.add('hidden');
        }

        if (dynamicSectionTitle) {
            dynamicSectionTitle.textContent = 'Processing...';
        }

        // 진행 상황 초기화 및 표시
        if (progressBar && progressPercentage) {
            progressBar.style.width = '0%';
            progressPercentage.textContent = '0%';
        }

        if (currentFileSpan && currentFileContainer) {
            currentFileSpan.textContent = '';
            currentFileContainer.classList.add('hidden');
        }

        if (progressContainer) {
            const additionalInfoContainer = document.createElement('div');
            additionalInfoContainer.id = 'additional-progress-info-container';
            additionalInfoContainer.className = 'mt-2 text-center';

            const additionalInfoSpan = document.createElement('span');
            additionalInfoSpan.id = 'additional-progress-info';
            additionalInfoSpan.className = 'text-xs text-slate-400 hidden';

            additionalInfoContainer.appendChild(additionalInfoSpan);
            progressContainer.appendChild(additionalInfoContainer);
        }

        // 시작 버튼 비활성화
        if (startButton) {
            startButton.disabled = true;
            startButton.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }

    // 처리 종료 함수
    function endProcessing(isSuccess = true) {
        isProcessing = false;
        endTime = new Date();

        hideLoading();

        // 시작 버튼 활성화
        if (startButton) {
            startButton.disabled = false;
            startButton.classList.remove('opacity-50', 'cursor-not-allowed');
        }

        // 진행 상황 컨테이너 숨기기
        if (progressContainer) {
            progressContainer.classList.add('hidden');
        }

        // 작업 유형에 따라 UI 요소 조정
        const foundKeyswrapper = document.getElementById('key-container-wrapper');
        const foundKeysContainer = document.getElementById('found-keys-container');
        const keyInputArea = document.getElementById('key-input-area');
        const dynamicSectionTitle = document.getElementById('dynamic-section-title');

        if (foundKeyswrapper && activeOperation !== 'decrypt') {
            foundKeyswrapper.classList.remove('hidden');
        }
        // 각 작업 유형별로 명확한 UI 상태 설정
        switch (activeOperation) {
            case 'find-key':
                // 키 찾기 작업 후에는 발견된 키 컨테이너 표시
                if (dynamicSectionTitle) {
                    dynamicSectionTitle.textContent = 'Found Keys';
                }

                if (foundKeysContainer) {
                    foundKeysContainer.classList.remove('hidden');
                }

                if (keyInputArea) {
                    keyInputArea.classList.add('hidden');
                }
                break;

            case 'decrypt':
                // 복호화 작업은 키가 필요 없음 - 항상 Found Keys 표시
                if (dynamicSectionTitle) {
                    dynamicSectionTitle.textContent = 'Found Keys';
                }

                if (foundKeysContainer) {
                    foundKeysContainer.classList.remove('hidden');
                }

                if (keyInputArea) {
                    keyInputArea.classList.add('hidden');
                }
                break;

            case 'encrypt':
            case 'reencrypt':
                // 암호화 작업은 항상 키 입력 필요 - Encryption Key 표시
                if (dynamicSectionTitle) {
                    dynamicSectionTitle.textContent = 'Encryption Key';
                }

                if (keyInputArea) {
                    keyInputArea.classList.remove('hidden');
                }

                if (foundKeysContainer) {
                    foundKeysContainer.classList.add('hidden');
                }
                break;
        }

        // 로그에 작업 완료 표시
        if (isSuccess) {
            logInfo(`${activeOperation} 작업이 완료되었습니다.`);
        }
    }

    // 결과 모달 표시 함수
    function showResultModal(operationName, totalFiles) {
        if (!resultModal || !operationNameSpan || !totalFilesSpan || !elapsedTimeSpan) return;

        operationNameSpan.textContent = operationName;
        totalFilesSpan.textContent = `${totalFiles}`;

        const elapsedMs = endTime - startTime;
        const seconds = Math.floor(elapsedMs / 1000);
        const minutes = Math.floor(seconds / 60);

        if (minutes > 0) {
            elapsedTimeSpan.textContent = `${minutes}min ${seconds % 60}sec`;
        } else {
            elapsedTimeSpan.textContent = `${seconds}sec`;
        }

        resultModal.classList.remove('hidden');
    }

    // 진행 상황 UI 업데이트 함수
    function updateProgressUI(info) {
        // 진행률 업데이트
        if (progressBar && progressPercentage) {
            progressBar.style.width = `${info.percentage}%`;
            progressPercentage.textContent = `${Math.floor(info.percentage)}%`;
        }

        // 현재 파일 정보 업데이트
        if (info.currentFile && currentFileSpan && currentFileContainer) {
            currentFileSpan.textContent = info.currentFile;
            currentFileContainer.classList.remove('hidden');
        }

        // 추가 정보 표시 (처리된 파일 수/전체 파일 수)
        const additionalInfoElement = document.getElementById('additional-progress-info');
        if (additionalInfoElement && info.totalCount > 0) {
            additionalInfoElement.textContent =
                `${info.processedCount}/${info.totalCount} proceeded ${info.timeInfo || ''}`;
            additionalInfoElement.classList.remove('hidden');
        }
    }

    // 이벤트 리스너 설정
    if (operationCards) {
        operationCards.forEach(card => {
            card.addEventListener('click', function() {
                // 라디오 버튼 선택
                const radio = this.querySelector('input[type="radio"]');
                if (radio) {
                    radio.checked = true;
                }

                // 선택된 카드 스타일 적용
                operationCards.forEach(c => c.classList.remove('selected'));
                this.classList.add('selected');

                // 선택된 작업에 따라 UI 조정
                const operation = radio ? radio.id.replace('-radio', '') : 'find-key';

                // 이미 같은 작업이 선택된 경우 무시
                if (activeOperation === operation) return;

                // 사용자 정의 경로가 있고 작업을 변경하는 경우
                if (customPathsMap.size > 0) {
                    showCustomConfirm(
                        "Changing operation will reset custom paths. Would you like to keep your custom paths?",
                        "Change Operation",
                        () => {
                            updateUIForOperation(operation, false, true); // 경로 유지 (OK 버튼 클릭)
                        },
                        () => {
                            updateUIForOperation(operation, false, false); // 경로 초기화 (No 버튼 클릭)
                        }
                    );
                } else {
                    updateUIForOperation(operation);
                }
            });
        });
    }

    // 커스텀 확인 다이얼로그 기능
    function showCustomConfirm(message, title = "Confirm", onConfirm, onCancel) {
        const modal = document.getElementById('custom-confirm-modal');
        const modalContent = modal.querySelector('div');
        const titleElement = document.getElementById('confirm-title');
        const messageElement = document.getElementById('confirm-message');
        const okButton = document.getElementById('confirm-ok-btn');
        const cancelButton = document.getElementById('confirm-cancel-btn');

        // 메시지와 타이틀 설정
        titleElement.textContent = title;
        messageElement.textContent = message;

        // 모달 표시
        modal.classList.remove('hidden');

        // 애니메이션 효과 (fade in)
        setTimeout(() => {
            modalContent.classList.remove('scale-95', 'opacity-0');
            modalContent.classList.add('scale-100', 'opacity-100');
        }, 10);

        // 버튼 이벤트 핸들러 설정
        const closeModal = () => {
            // 애니메이션 효과 (fade out)
            modalContent.classList.remove('scale-100', 'opacity-100');
            modalContent.classList.add('scale-95', 'opacity-0');

            setTimeout(() => {
                modal.classList.add('hidden');
            }, 200);

            // 이벤트 리스너 제거
            okButton.removeEventListener('click', handleConfirm);
            cancelButton.removeEventListener('click', handleCancel);
        };

        const handleConfirm = () => {
            closeModal();
            if (onConfirm) onConfirm();
        };

        const handleCancel = () => {
            closeModal();
            if (onCancel) onCancel();
        };

        // 이벤트 리스너 등록
        okButton.addEventListener('click', handleConfirm);
        cancelButton.addEventListener('click', handleCancel);
    }

    // 게임 버전 버튼 설정
    if (mvButton && mzButton) {
        mvButton.addEventListener('click', function() {
            // MV 버튼 활성화
            mvButton.classList.add('active');
            mzButton.classList.remove('active');

            // 화살표 표시 조정
            const rightArrow = mvButton.querySelector('.right-arrow');
            const leftArrow = mzButton.querySelector('.left-arrow');

            if (rightArrow) rightArrow.classList.remove('hidden');
            if (leftArrow) leftArrow.classList.add('hidden');

            // 게임 버전 설정
            gameVersion = 'MV';

            // 애니메이션 효과
            mvButton.style.zIndex = '2';
            mzButton.style.zIndex = '1';
        });

        mzButton.addEventListener('click', function() {
            // MZ 버튼 활성화
            mzButton.classList.add('active');
            mvButton.classList.remove('active');

            // 화살표 표시 조정
            const rightArrow = mvButton.querySelector('.right-arrow');
            const leftArrow = mzButton.querySelector('.left-arrow');

            if (rightArrow) rightArrow.classList.add('hidden');
            if (leftArrow) leftArrow.classList.remove('hidden');

            // 게임 버전 설정
            gameVersion = 'MZ';

            // 애니메이션 효과
            mzButton.style.zIndex = '2';
            mvButton.style.zIndex = '1';
        });

        // 초기 상태 설정
        if (mvButton.classList.contains('active')) {
            const rightArrow = mvButton.querySelector('.right-arrow');
            if (rightArrow) rightArrow.classList.remove('hidden');
        }
    }

    // 시작 버튼 이벤트
    if (startButton) {
        startButton.addEventListener('click', startOperation);
    }

    // 폴더 새로고침 버튼 이벤트
    if (refreshFoldersButton) {
        // 기존 이벤트 리스너 제거 후 다시 등록
        refreshFoldersButton.removeEventListener('click', scanFolders);
        refreshFoldersButton.addEventListener('click', function(e) {
            // 중복 클릭 방지
            if (isScanning) {
                logInfo("이미 스캔 중입니다.");
                return;
            }

            // 사용자 정의 경로 초기화
            customPathsMap.clear();

            // 새 스캔 시작
            scanFolders();
        });
    }

    // 모달 닫기 버튼 이벤트
    if (closeModalButton) {
        closeModalButton.addEventListener('click', function() {
            if (resultModal) {
                resultModal.classList.add('hidden');
            }
        });
    }

    // 앱 시작 시 기본 경로 가져오기
    if (window.pywebview && window.pywebview.api) {
        window.pywebview.api.get_base_path()
            .then(path => {
                logInfo(`기본 경로: ${path}`);
            })
            .catch(err => {
                logInfo(`기본 경로 불러오기 실패: ${err}`, true);
            });
    }

    // 작업 완료 이벤트 리스너
    window.addEventListener('operation-complete', function(event) {
        const data = event.detail;

        if (data && data.data) {
            const result = data.data;
            endProcessing(true);

            // 작업 유형에 따른 결과 처리
            switch (activeOperation) {
                case 'find-key':
                    if (result.keys && result.keys.length > 0) {
                        displayFoundKeys(result.keys);
                        logInfo(`${result.keys.length}개의 암호화 키를 찾았습니다`);
                    } else {
                        logWarn('암호화 키를 찾을 수 없습니다');
                    }
                    break;

                case 'decrypt':
                case 'encrypt':
                case 'reencrypt':
                    if (result.status === 'success') {
                        const operationDisplayName = {
                            'decrypt': 'Decrypt',
                            'encrypt': 'Encrypt',
                            'reencrypt': 'Re-encrypt'
                        }[activeOperation] || activeOperation;

                        logInfo(`${operationDisplayName} 완료: ${result.processedFiles || 0}개 파일 처리됨`);
                        showResultModal(operationDisplayName, result.processedFiles || 0);
                    } else {
                        logWarn(`${activeOperation} 작업 실패`);
                    }
                    break;
            }
        }
    });

    // 작업 오류 이벤트 리스너
    window.addEventListener('operation-error', function(event) {
        const data = event.detail;

        if (data && data.data) {
            endProcessing(false);
            logError(`작업 오류: ${data.data.message || '알 수 없는 오류'}`);
        }
    });

    // 디버그 메시지 이벤트 리스너
    window.addEventListener('debug-message', function(event) {
        const data = event.detail;

        if (data && data.data && data.data.message) {
            const message = data.data.message;

            if (message.includes('Error') || message.includes('Failed') ||
                message.includes('오류') || message.includes('실패')) {
                logError(message);
            } else if (message.includes('Warning') || message.includes('경고')) {
                logWarn(message);
            } else {
                logInfo(message);
            }
        }
    });

    // 로딩 인디케이터 함수
    function showLoading(messageText) {
        const loadingIndicator = document.getElementById('loading-indicator');

        // 메시지 텍스트가 없으면 기본값 사용
        const displayMessage = messageText || "처리 중...";

        const loadingHTML = `
            <div class="bg-slate-800 p-4 rounded-md shadow-lg flex flex-col items-center">
                <div class="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500 mb-3"></div>
                <p class="text-slate-300">${displayMessage}</p>
            </div>
        `;

        if (loadingIndicator) {
            loadingIndicator.innerHTML = loadingHTML;
            loadingIndicator.classList.remove('hidden');
        } else {
            // 로딩 인디케이터가 없으면 동적으로 생성
            const newLoadingIndicator = document.createElement('div');
            newLoadingIndicator.id = 'loading-indicator';
            newLoadingIndicator.className = 'fixed inset-0 flex items-center justify-center bg-slate-900 bg-opacity-70 z-50';
            newLoadingIndicator.innerHTML = loadingHTML;
            document.body.appendChild(newLoadingIndicator);
        }
    }

    function hideLoading() {
        const loadingIndicator = document.getElementById('loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.classList.add('hidden');
        }
    }

    // 툴팁 관련 함수들
    function initializeTooltips() {
        // 툴팁 콘텐츠 정의
        const operationTooltips = {
            'find-key': "System(.json), .rpgmvp, .png_ files are required to find the encryption key",
            'decrypt': "Decrypt encrypted game files automatically",
            'encrypt': "Encrypt decrypted files for game distribution",
            'reencrypt': "Change encryption key while keeping files encrypted"
        };

        // 각 info-icon에 이벤트 리스너 추가
        document.querySelectorAll('.operation-card .info-icon').forEach(icon => {
            // 가장 가까운 operation-card 부모 요소를 찾음
            const card = icon.closest('.operation-card');
            if (!card) return;

            // 카드의 ID에서 작업 유형 추출 (예: "find-key-card" -> "find-key")
            const operationType = card.id.replace('-card', '');

            // 툴팁 콘텐츠 가져오기
            const tooltipContent = operationTooltips[operationType];
            if (!tooltipContent) return;

            // 마우스 오버 이벤트 리스너
            icon.addEventListener('mouseenter', function(e) {
                showTooltip(icon, tooltipContent);
            });

            // 마우스 아웃 이벤트 리스너
            icon.addEventListener('mouseleave', function() {
                hideTooltip();
            });
        });
    }

    // 툴팁 표시 함수
    function showTooltip(element, content) {
        // 기존 툴팁 제거
        hideTooltip();

        // 새 툴팁 요소 생성
        const tooltip = document.createElement('div');
        tooltip.id = 'tooltip';
        tooltip.className = 'tooltip bg-slate-800 text-white text-sm px-3 py-2 rounded shadow-lg absolute z-50';
        tooltip.textContent = content;
        tooltip.style.maxWidth = '250px';

        // 툴팁 위치 계산을 위해 먼저 body에 추가
        document.body.appendChild(tooltip);

        // 요소 위치 계산
        const rect = element.getBoundingClientRect();
        const tooltipRect = tooltip.getBoundingClientRect();

        // 툴팁 위치 설정 (요소 위에 배치)
        tooltip.style.left = `${rect.left + (rect.width / 2) - (tooltipRect.width / 2)}px`;
        tooltip.style.top = `${rect.top - tooltipRect.height - 10}px`;

        // 뷰포트 경계를 벗어나는지 확인하고 조정
        const rightEdge = tooltip.getBoundingClientRect().right;
        if (rightEdge > window.innerWidth) {
            tooltip.style.left = `${window.innerWidth - tooltipRect.width - 10}px`;
        }

        // 애니메이션 효과
        tooltip.style.opacity = '0';
        tooltip.style.transition = 'opacity 0.3s ease';

        // 약간의 지연 후 표시
        setTimeout(() => {
            tooltip.style.opacity = '1';
        }, 0);
    }

    // 툴팁 숨기기 함수
    function hideTooltip() {
        const tooltip = document.getElementById('tooltip');
        if (tooltip) {
            // 애니메이션과 함께 제거
            tooltip.style.opacity = '0';
            setTimeout(() => {
                tooltip.remove();
            }, 0);
        }
    }

    // 설정 메뉴 기능 구현
    function initializeSettingsMenu() {
        const settingsButton = document.getElementById('settings-button');
        const settingsMenu = document.getElementById('settings-menu');

        if (!settingsButton || !settingsMenu) return;

        // 설정 버튼 클릭 이벤트
        settingsButton.addEventListener('click', function(e) {
            e.stopPropagation(); // 이벤트 버블링 방지
            settingsMenu.classList.toggle('hidden');
        });

        // 메뉴 항목별 이벤트
        const menuItems = {
            'about-menu': {
                title: 'About MVMZ-Crypter',
                content: `MVMZ-Crypter v${version}<br><br>◈A simple and efficient tool<br>　for managing files for RPG Maker MV and MZ.<br><br>◈Developed by Tasteful-1`
            },
            'help-menu': {
                title: 'Help (For when not using Add List)',
                content: '0. Basic Setup <br>* For decryption :<br>　Place encrypted files/folders in the <code class="styled-code">encrypted</code> folder next to the program executable.<br>* For encryption :<br>　Place non-encrypted files/folders in the <code class="styled-code">decrypted</code> folder next to the program executable.<br>* For re-encryption :<br>　Place encrypted files/folders in the <code class="styled-code">encrypted</code> folder next to the program executable.<br>※ Warning<br>* To decrypt or re-encrypt audio files,<br>　you must place an image file or system.json,<br>　encrypted with the same key into the audio folder.<br>1. Finding Encryption Keys<br>* Choose <code class="styled-code">Find Encryption Key</code> → Select files/folders in the <code class="styled-code">encrypted</code> folder → Click <code class="styled-code">Start</code>.<br>* Keys are automatically found from System.json or encrypted image files.<br>* Found keys are displayed and can be copied.<br>2. File Decryption<br>* Choose <code class="styled-code">Decrypt Files</code> → Select files/folders in the <code class="styled-code">encrypted</code> folder → Click <code class="styled-code">Start</code>.　　　　　　　　　　　　　　<br>* Keys are found automatically (no manual entry needed).<br>* Decrypted files are saved in the <code class="styled-code">decrypted</code> folder.<br>3. File Encryption<br>*  Choose <code class="styled-code">Encrypt Files</code> → Select files/folders in the <code class="styled-code">decrypted</code> folder.<br>* Enter an encryption key (required).<br>* Select game version (MV/MZ) and click <code class="styled-code">Start</code>.<br>* Encrypted files are saved in the <code class="styled-code">encrypted</code> folder.<br>4. File Re-encryption<br>* Choose <code class="styled-code">Re-encrypt Files</code> → Select files/folders in the <code class="styled-code">encrypted</code> folder.<br>* Enter a new encryption key (required).<br>* Select game version (MV/MZ) and click <code class="styled-code">Start</code>.<br>* Original keys are found automatically.<br>* Re-encrypted files are saved in the <code class="styled-code">re-encrypted</code> folder.<br>5. Common Operations<br>* Multiple folders/files can be selected simultaneously.<br>* Use the <code class="styled-code">Refresh</code> button to update the folder list.<br>* Check the number of processed files and elapsed time upon completion.<br>'},
            'license-menu': {
                title: 'License',
                content: 'MIT License<br><br>Copyright (c) 2023-2025 Tasteful-1<br><br>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:<br><br>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.<br><br>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'
            },
            'references-menu': {
                title: 'References',
                content: '◈ RPG-Maker-MV-Decrypter<br>　MIT License<br>　Copyright (c) 2016 Peter Dragicevic'
            }
        };

        Object.entries(menuItems).forEach(([id, data]) => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('click', function(e) {
                    e.preventDefault();
                    showInfoModal(data.title, data.content);
                    settingsMenu.classList.add('hidden');
                });
            }
        });

        // 문서 클릭 시 메뉴 닫기
        document.addEventListener('click', function() {
            settingsMenu.classList.add('hidden');
        });

        // 메뉴 내부 클릭 시 이벤트 버블링 방지
        settingsMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });

        logInfo('설정 메뉴 초기화 완료');
    }

    // 정보 모달 창 표시 함수
    function showInfoModal(title, content) {
        // 모달 HTML 생성
        const modalHTML = `
        <div id="info-modal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-slate-800 rounded-lg shadow-xl p-6 w-full relative" style="max-width: 48rem; min-width: 32rem;width: auto;">
                <!-- X 버튼 (우상단) -->
                <button id="close-info-modal" class="absolute top-4 right-4 text-slate-400 hover:text-white">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>

                <!-- 타이틀 -->
                <h2 class="text-xl font-bold mb-2 text-white">${title}</h2>

                <!-- 구분선 -->
                <div class="border-t border-slate-600 mb-4 mt-2"></div>

                <!-- 내용 -->
                <div class="text-slate-300 overflow-y-auto" style="max-height: 60vh">
                    ${content}
                </div>
            </div>
        </div>
        `;

        // 기존 모달 제거
        const existingModal = document.getElementById('info-modal');
        if (existingModal) {
            existingModal.remove();
        }

        // 새 모달 추가
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // 닫기 버튼 이벤트
        document.getElementById('close-info-modal').addEventListener('click', function() {
            document.getElementById('info-modal').remove();
        });

        logInfo(`모달 표시: ${title}`);
    }

    if (closeresultButton) {
        closeresultButton.addEventListener('click', function() {
            if (resultModal) {
                resultModal.classList.add('hidden');
            }
        });
    }

    // 경로 관리를 위한 변수 추가
    let customPathsMap = new Map(); // 키: 표시 이름, 값: {originalPath: 경로, type: 'file'|'folder'}
    const addFolderButton = document.getElementById('add-folder-button');

    // 추가된 경로 처리 함수
    function processAddedPath(path, type) {
        // 경로에서 이름 추출 (마지막 부분)
        const pathParts = path.split(/[\/\\]/);
        const displayName = pathParts[pathParts.length - 1] || path;

        // 경로명이 이미 존재하는지 확인
        let uniqueName = displayName;
        let counter = 1;

        // 이름 중복 확인 및 처리
        while (selectedFolders.includes(uniqueName) || customPathsMap.has(uniqueName)) {
            uniqueName = `${displayName} (${counter})`;
            counter++;
        }

        // 맵에 추가
        customPathsMap.set(uniqueName, {
            originalPath: path,
            type: type
        });

        // 새로 추가된 항목을 선택된 폴더 목록에 추가
        selectedFolders.push(uniqueName);

        // 폴더 리스트 갱신
        updateFolderListWithCustomPaths();
    }

    // 기존 updateFolderList
    function updateFolderListWithCustomPaths() {
        // 기존 폴더 목록 유지
        // 사용자 정의 경로만 추가
        for (const [displayName, pathData] of customPathsMap.entries()) {
            // 이미 목록에 있는지 확인
            const existingItem = Array.from(folderList.querySelectorAll('div'))
                .find(div => {
                    const nameSpan = div.querySelector('span:nth-child(3)');
                    return nameSpan && nameSpan.textContent === displayName;
                });

            if (existingItem) continue;

            // 폴더 항목 생성
            const folderItem = document.createElement('div');
            folderItem.className = 'flex items-center p-3 hover:bg-slate-700 border-b border-slate-700 cursor-pointer custom-path-item';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'mr-3';
            checkbox.checked = selectedFolders.includes(displayName);

            // 파일 타입에 맞는 아이콘
            const icon = document.createElement('span');
            icon.className = 'mr-2';
            icon.textContent = pathData.type === 'folder' ? '📁' : '📄';

            const folderName = document.createElement('span');
            folderName.className = 'text-slate-300';
            folderName.textContent = displayName;

            // 삭제 버튼 추가
            const deleteButton = document.createElement('button');
            deleteButton.className = 'ml-auto text-slate-400 hover:text-red-500';
            deleteButton.innerHTML = '✕';
            deleteButton.title = 'Delete';
            deleteButton.onclick = (e) => {
                e.stopPropagation(); // 클릭 이벤트 전파 방지
                removeCustomPath(displayName);
            };

            // 원본 경로 정보 추가
            const pathOrigin = document.createElement('div');
            pathOrigin.className = 'path-origin';
            pathOrigin.textContent = `Added`;
            //pathOrigin.textContent = `Added: ${pathData.originalPath}`;

            // 항목 구성
            folderItem.appendChild(checkbox);
            folderItem.appendChild(icon);
            folderItem.appendChild(folderName);
            folderItem.appendChild(deleteButton);

            // 체크박스 상태 변경 이벤트 핸들러
            function toggleCheckboxState() {
                checkbox.checked = !checkbox.checked;

                if (checkbox.checked) {
                    if (!selectedFolders.includes(displayName)) {
                        selectedFolders.push(displayName);
                    }
                } else {
                    const index = selectedFolders.indexOf(displayName);
                    if (index > -1) {
                        selectedFolders.splice(index, 1);
                    }
                }
                updateSelectedCount();
            }

            // 이벤트 리스너 추가
            folderItem.addEventListener('click', function(e) {
                if (e.target !== checkbox) {
                    toggleCheckboxState();
                }
            });

            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    if (!selectedFolders.includes(displayName)) {
                        selectedFolders.push(displayName);
                    }
                } else {
                    const index = selectedFolders.indexOf(displayName);
                    if (index > -1) {
                        selectedFolders.splice(index, 1);
                    }
                }
                updateSelectedCount();
            });

            // 리스트에 추가
            folderList.appendChild(folderItem);
        }

        updateSelectedCount();
    }

    // 기존 updateFolderList 함수 수정
    const originalUpdateFolderList = updateFolderList;
    updateFolderList = function(folders) {
        // 원래 기능 호출
        originalUpdateFolderList(folders);

        // 사용자 정의 경로 추가
        updateFolderListWithCustomPaths();
    };

    // 작업 실행 함수 수정하여 결과 경로 처리
    const originalStartOperation = startOperation;
    startOperation = function() {
        logDebug(`Custom paths map size: ${customPathsMap.size}`,
            Array.from(customPathsMap.entries()));
        // 작업 시작 전 원본 경로와 표시 이름의 매핑 정보를 Python에 전달
        if (customPathsMap.size > 0 && window.pywebview && window.pywebview.api) {
            const pathMappings = {};
            for (const [displayName, pathData] of customPathsMap.entries()) {
                pathMappings[displayName] = {
                    originalPath: pathData.originalPath,
                    type: pathData.type
                };
            }

            // 작업 유형에 따른 결과 경로 표식 결정
            let pathSuffix = '';
            switch (activeOperation) {
                case 'decrypt':
                    pathSuffix = '_decrypted';
                    break;
                case 'encrypt':
                    pathSuffix = '_encrypted';
                    break;
                case 'reencrypt':
                    pathSuffix = '_reencrypted';
                    break;
            }

            logInfo('경로 매핑 정보 설정 중...');

            // 경로 매핑 정보 저장
            window.pywebview.api.set_path_mappings(pathMappings, pathSuffix)
                .then(result => {
                    if (result && result.success) {
                        logInfo('경로 매핑 정보가 저장되었습니다.');
                        // 원래 작업 실행
                        originalStartOperation();
                    } else {
                        logError(`경로 매핑 저장 실패: ${result.error || '알 수 없는 오류'}`);
                        // 에러가 발생해도 원래 작업은 실행
                        originalStartOperation();
                    }
                })
                .catch(error => {
                    logError(`경로 매핑 저장 중 오류: ${error.message || error}`);
                    // 에러가 발생해도 원래 작업은 실행
                    originalStartOperation();
                });
        } else {
            // 사용자 정의 경로가 없으면 그냥 원래 작업 실행
            originalStartOperation();
        }
    };

    // 사용자 정의 경로 제거 함수
    function removeCustomPath(displayName) {
        // customPathsMap에서 제거
        if (customPathsMap.has(displayName)) {
            customPathsMap.delete(displayName);

            // selectedFolders에서도 제거
            const index = selectedFolders.indexOf(displayName);
            if (index > -1) {
                selectedFolders.splice(index, 1);
            }

            // DOM에서 해당 항목 제거
            const items = folderList.querySelectorAll('div.custom-path-item');
            for (const item of items) {
                const nameSpan = item.querySelector('span:nth-child(3)');
                if (nameSpan && nameSpan.textContent === displayName) {
                    folderList.removeChild(item);
                    break;
                }
            }

            // 선택된 폴더 수 업데이트
            updateSelectedCount();

            logInfo(`경로 제거됨: ${displayName}`);
        }
    }

    // 드롭다운 메뉴 동작 코드
    function initializeAddPathDropdown() {
        const addPathButton = document.getElementById('add-path-button');
        const pathMenu = document.getElementById('path-menu');
        const addFolderOption = document.getElementById('add-folder-option');
        const addFileOption = document.getElementById('add-file-option');

        if (!addPathButton || !pathMenu) return;

        // 드롭다운 토글
        addPathButton.addEventListener('click', function(e) {
            e.stopPropagation();
            pathMenu.classList.toggle('hidden');
        });

        // 폴더 추가 옵션
        if (addFolderOption) {
            addFolderOption.addEventListener('click', function() {
                addCustomPath(true); // true = 폴더 모드
                pathMenu.classList.add('hidden');
            });
        }

        // 파일 추가 옵션
        if (addFileOption) {
            addFileOption.addEventListener('click', function() {
                addCustomPath(false); // false = 파일 모드
                pathMenu.classList.add('hidden');
            });
        }

        // 메뉴 외부 클릭 시 닫기
        document.addEventListener('click', function() {
            if (pathMenu) pathMenu.classList.add('hidden');
        });
    }

    // 사용자 정의 경로 추가 함수 수정
    function addCustomPath(selectFolder = true) {
        if (isProcessing) {
            logInfo("처리 중에는 파일/폴더를 추가할 수 없습니다.");
            return;
        }

        logInfo(`${selectFolder ? '폴더' : '파일'} 추가 다이얼로그 열기...`);

        // Python API 호출
        if (window.pywebview && window.pywebview.api) {
            window.pywebview.api.show_file_dialog(selectFolder)
                .then(result => {
                    if (result && result.path) {
                        if (result.isDirectory) {
                            // 폴더는 단일 문자열
                            processAddedPath(result.path, 'folder');
                            logInfo(`새 폴더 추가됨: ${result.path}`);
                        } else {
                            // 파일은 배열
                            const paths = Array.isArray(result.path) ? result.path : [result.path];
                            paths.forEach(p => {
                                processAddedPath(p, 'file');
                                logInfo(`새 파일 추가됨: ${p}`);
                            });
                        }
                    }
                })
                .catch(error => {
                    logError(`파일/폴더 추가 중 오류: ${error.message || error}`);
                });
        }
    }

    //설정 메뉴 초기화
    initializeSettingsMenu();
    // 초기 UI 상태 설정
    initializeApplication();
});