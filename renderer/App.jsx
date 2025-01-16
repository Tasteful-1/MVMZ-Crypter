import React, { useState, useEffect, useCallback } from 'react';
import { useSettings } from './SettingsContext';
import { useTheme } from './ThemeContext';
import MainField from './MainField';
import SettingsMenu from './SettingsMenu';
import ResultModal from './ResultModal';
import { FolderTree } from 'lucide-react';

const Operation = {
  FIND_KEY: 'find_key',
  DECRYPT: 'decrypt',
  ENCRYPT: 'encrypt',
  REENCRYPT: 'reencrypt'
};

const getOperationName = (operation) => {
	const names = {
	  'find_key': 'Find_key',
	  'decrypt': 'Decrypt',
	  'encrypt': 'Encrypt',
	  'reencrypt': 'Re-encrypt'
	};
	return names[operation] || operation;
  };

function App() {
  const { theme } = useTheme();
  const { cleanFolders } = useSettings();
  
  // 상태 관리
  const [selectedOperation, setSelectedOperation] = useState(Operation.FIND_KEY);
  const [availableFolders, setAvailableFolders] = useState([]);
  const [selectedFolders, setSelectedFolders] = useState([]);
  const [foundKeys, setFoundKeys] = useState(new Map());
  const [encryptionKey, setEncryptionKey] = useState('');
  const [newEncryptionKey, setNewEncryptionKey] = useState('');
  const [gameVersion, setGameVersion] = useState('mv');
  
  // 진행 상태 관리
  const [isProcessing, setIsProcessing] = useState(false);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [showProgress, setShowProgress] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentFile, setCurrentFile] = useState('');
  const [startTime, setStartTime] = useState(null);
  const [endTime, setEndTime] = useState(null);

  // 결과 모달 관련 상태 추가
  const [showResultModal, setShowResultModal] = useState(false);
  const [processedFiles, setProcessedFiles] = useState(0);
  const [error, setError] = useState(null);

  // 폴더 스캔 함수
  const scanFolders = useCallback(async () => {
    if (!window.mvmz) return;

    try {
      setSelectedFolders([]);
      setFoundKeys(new Map());

      await window.mvmz.sendCommand({
        type: 'scan_folders',
        data: {
          source: selectedOperation === Operation.ENCRYPT ? 'decrypted' : 'encrypted'
        }
      });
    } catch (error) {
      console.error('Failed to scan folders:', error);
    }
  }, [selectedOperation]);

  // Operation 변경 핸들러
  const handleOperationChange = useCallback((operation) => {
    setSelectedOperation(operation);
    setSelectedFolders([]);
    setFoundKeys(new Map());
    setEncryptionKey('');
    setNewEncryptionKey('');
    setProgress(0);
    setCurrentFile('');
    scanFolders();
  }, [scanFolders]);

  // 폴더 선택 토글
  const toggleFolderSelection = useCallback((folder) => {
    setSelectedFolders(prev =>
      prev.includes(folder)
        ? prev.filter(f => f !== folder)
        : [...prev, folder]
    );
  }, []);

  // 작업 시작 핸들러
  const startOperation = useCallback(async () => {
    const now = Date.now();
    setIsProcessing(true);
    setProgress(0);
    setCurrentFile('');
	setStartTime(now);
    setEndTime(null);
    setShowProgress(true);
	setShowResultModal(false);  // 결과 모달 초기화
    setProcessedFiles(0);  // 처리된 파일 수 초기화

    try {
      const command = {
        type: selectedOperation,
        data: {
          folders: selectedFolders,
          key: selectedOperation === Operation.REENCRYPT ? newEncryptionKey : encryptionKey,
          cleanFolders,
          gameVersion
        }
      };
      await window.mvmz.sendCommand(command);
    } catch (error) {
      setIsProcessing(false);
      setShowProgress(false);
	  setEndTime(Date.now());
      alert('Operation failed: ' + error.message);
    }
  }, [selectedFolders, selectedOperation, encryptionKey, newEncryptionKey, cleanFolders, gameVersion]);

  useEffect(() => {
    let intervalId;
    
    if (startTime && !endTime) {
      // 초기 시간 설정
      setElapsedTime(Math.floor((Date.now() - startTime) / 1000));
      
      // 1초마다 업데이트
      intervalId = setInterval(() => {
        setElapsedTime(Math.floor((Date.now() - startTime) / 1000));
      }, 1000);
    } else if (startTime && endTime) {
      // 작업이 완료된 경우 최종 시간 설정
      setElapsedTime(Math.floor((endTime - startTime) / 1000));
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [startTime, endTime]);

  // 프로그레스 타이머 관리
  useEffect(() => {
    let clearProgressTimer;
    if (showProgress && !isProcessing) {
      clearProgressTimer = setTimeout(() => {
        setShowProgress(false);
        setProgress(0);
        setCurrentFile('');
		// 여기에서 결과 모달을 표시
        if (processedFiles > 0 && !error) {
          setShowResultModal(true);
        }
      }, 0);
    }
    return () => {
      if (clearProgressTimer) clearTimeout(clearProgressTimer);
    };
  }, [showProgress, isProcessing, processedFiles, error]);

  // 초기 폴더 스캔
  useEffect(() => {
    scanFolders();
  }, [scanFolders]);

  // 메시지 핸들러 설정
  useEffect(() => {
    if (!window.mvmz) {
      console.error('MVMZ bridge not initialized');
      return;
    }

    const messageHandler = (message) => {
		if (message.type === 'progress') {
			const { progress, currentFile } = message.data;

			setShowProgress(true);
			setProgress(progress);
			setCurrentFile(currentFile);
		  } else if (message.type === 'complete') {
			const end = Date.now();

			if (message.data.processedFiles) {
			  setProcessedFiles(message.data.processedFiles);
			}
			setEndTime(end);
			setIsProcessing(false);
			setError(null); // 성공 시 에러 상태 초기화

		if (message.data.processedFiles) {  // 추가
			setProcessedFiles(message.data.processedFiles);
		  }
		 // 추가 데이터 처리
      	if (message.data.folders) {
        setAvailableFolders(message.data.folders);
     	}
        if (message.data.keys) {
          const newKeys = new Map();
          message.data.keys.forEach(({ key, folders }) => {
            if (folders && folders.length > 0) {
              newKeys.set(key, folders);
            }
          });
          setFoundKeys(newKeys);
          if (newKeys.size > 0) {
            setEncryptionKey([...newKeys.keys()][0]);
          }
        }
        setEndTime(Date.now());
        setIsProcessing(false);
      } else if (message.type === 'error') {
        setIsProcessing(false);
        setShowProgress(false);
		setEndTime(Date.now());
		setError(message.data.message); // 에러 상태 설정
        alert(message.data.message);
      }
    };

    const cleanup = window.mvmz.onMessage(messageHandler);
    return () => {
      if (cleanup) cleanup();
      if (window.mvmz.removeListeners) {
        window.mvmz.removeListeners();
      }
    };
  }, []);

  return (
    <div className="min-h-screen p-6 select-none bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white">
      <div className="max-w-5xl mx-auto">
        <header className="bg-slate-800 text-white p-4 rounded-lg mb-6">
          <div className="flex justify-between items-center">
            <h1 className="text-xl font-bold flex items-center gap-2 dark:text-slate-300">
              <FolderTree className="w-6 h-6" />
              MVMZ-Crypter v2.0.2
            </h1>
            <SettingsMenu />
          </div>
        </header>

        <div className={`${
          theme === 'dark'
          ? 'bg-slate-800 border-slate-700'
          : 'bg-white border-slate-200'
        } rounded-lg shadow-sm border p-6`}>
          <div className="flex gap-6">
            <div className="w-80">
              <div className="flex justify-between items-center mb-2">
                <h2 className="text-sm font-semibold dark:text-slate-300">
                  Select Folders ({selectedFolders.length} selected)
                </h2>
                <button
                  onClick={scanFolders}
                  className="text-xs text-blue-600 hover:text-blue-800"
                  tabIndex="-1"
                >
                  Refresh
                </button>
              </div>
              <div className="bg-slate-50 rounded-lg p-4 dark:bg-slate-900">
                <div className={`
				bg-white dark:bg-slate-800 rounded border border-slate-200 dark:border-slate-700 p-3 overflow-y-auto
				${selectedOperation === Operation.FIND_KEY ? 'h-[450px]' : 'h-96'}
				`}>
                  {availableFolders.map(folder => (
                    <div
                      key={folder}
                      onClick={() => toggleFolderSelection(folder)}
                      className={`select-none flex items-center gap-2 mb-2 p-2
                      hover:bg-slate-50 dark:hover:bg-slate-700/50 rounded cursor-pointer
                      ${selectedFolders.includes(folder) 
                        ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800' 
                        : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedFolders.includes(folder)}
                        onChange={() => toggleFolderSelection(folder)}
                        className="w-4 h-4 text-blue-600 rounded border-slate-300 dark:border-slate-600
                          focus:ring-blue-500 dark:focus:ring-blue-600"
                        onClick={(e) => e.stopPropagation()}
                      />
                      <span className="flex-1 text-slate-700 dark:text-slate-300">
                        <span className="text-slate-400 mr-2">📁</span>
                        {folder}
                        {encryptionKey && foundKeys.has(encryptionKey) &&
                        foundKeys.get(encryptionKey).includes(folder) && (
                          <span className="ml-2 text-yellow-500" title={`Using key: ${encryptionKey}`}>
                            🔑
                          </span>
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Main Field */}
            <MainField
              selectedOperation={selectedOperation}
              setSelectedOperation={handleOperationChange}
              encryptionKey={encryptionKey}
              setEncryptionKey={setEncryptionKey}
              newEncryptionKey={newEncryptionKey}
              setNewEncryptionKey={setNewEncryptionKey}
              isProcessing={isProcessing}
              progress={progress}
              currentFile={currentFile}
              gameVersion={gameVersion}
              setGameVersion={setGameVersion}
              onStartOperation={startOperation}
              foundKeys={foundKeys}
              selectedFolders={selectedFolders}
			  startTime={startTime}
			  endTime={endTime}
            />
          </div>
        </div>
      </div>
      {/* Result Modal */}
      {showResultModal && (
        <ResultModal
          isOpen={showResultModal}
          onClose={() => setShowResultModal(false)}
          operationName={getOperationName(selectedOperation)}
          totalFiles={processedFiles}
          startTime={startTime}
          endTime={endTime}
        />
      )}
    </div>
  );
}

export default App;