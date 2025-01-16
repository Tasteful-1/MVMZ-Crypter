import React, { useState } from 'react';
import {
  Search,
  Unlock,
  Lock,
  RefreshCw,
  X,
  HelpCircle
} from 'lucide-react';
import KeySlider from './KeySlider';
import ProgressBar from './ProgressBar';
import { useTheme } from './ThemeContext';

// Operation 타입 정의
const Operation = {
	FIND_KEY: 'find_key',
	DECRYPT: 'decrypt',
	ENCRYPT: 'encrypt',
	REENCRYPT: 'reencrypt'
  };

  // Operation별 툴팁 텍스트 정의
  const operationTooltips = {
	[Operation.FIND_KEY]: "System(.json), .rpgmvp, .png_ files are required to find the encryption key",
	[Operation.DECRYPT]: "Decrypt encrypted game files with the provided key",
	[Operation.ENCRYPT]: "Encrypt decrypted files for game distribution",
	[Operation.REENCRYPT]: "Change encryption key while keeping files encrypted"
  };

  // operations 배열 정의
  const operations = [
	{
	  id: Operation.FIND_KEY,
	  label: 'Find Encryption Key',
	  icon: Search
	},
	{
	  id: Operation.DECRYPT,
	  label: 'Decrypt Files',
	  icon: Unlock
	},
	{
	  id: Operation.ENCRYPT,
	  label: 'Encrypt Files',
	  icon: Lock
	},
	{
	  id: Operation.REENCRYPT,
	  label: 'Re-encrypt Files',
	  icon: RefreshCw
	}
  ];

  // OperationSelector 컴포넌트
  const OperationSelector = ({ selectedOperation, onSelect }) => {
	const [tooltipVisible, setTooltipVisible] = React.useState('');

	return (
	  <div className="space-y-1">
		{operations.map(({ id, label, icon: Icon }) => (
		  <label
			key={id}
			className="flex items-center justify-between p-3 hover:bg-slate-50 dark:bg-slate-900 rounded-lg transition-colors cursor-pointer"
		  >
			<div className="flex items-center gap-3">
			  <input
				type="radio"
				name="operation"
				value={id}
				checked={selectedOperation === id}
				onChange={() => onSelect(id)}
				className="hidden"
			  />
			  <div
				className={`w-5 h-5 rounded-full border-2 flex items-center justify-center
				  ${selectedOperation === id ? 'border-blue-600 bg-blue-600' : 'border-slate-300'}`}
			  >
				{selectedOperation === id && (
				  <div className="w-2 h-2 rounded-full bg-white" />
				)}
			  </div>
			  <div className="flex items-center gap-2 dark:text-slate-300">
				<Icon className="w-4 h-4" />
				<span>{label}</span>
			  </div>
			</div>

			{/* 툴팁 버튼 */}
			<button
			  className="group relative flex-shrink-0 text-slate-400 hover:text-slate-600"
			  onMouseEnter={() => setTooltipVisible(id)}
			  onMouseLeave={() => setTooltipVisible('')}
			>
			  <HelpCircle className="w-4 h-4" />
			  {tooltipVisible === id && (
				<div className="absolute right-0 top-full mt-2 bg-slate-800 text-white text-xs p-2 rounded w-64 z-10">
				  {operationTooltips[id]}
				</div>
			  )}
			</button>
		  </label>
		))}
	  </div>
	);
  };

// Key Input Component
const KeyInput = ({ value, onChange, placeholder, readOnly = false }) => {
	const { theme } = useTheme();
	
	return (
	  <div className="relative">
		<input
		  type="text"
		  value={value}
		  onChange={(e) => onChange(e.target.value)}
		  readOnly={readOnly}
		  className={`
			w-full px-3 py-2 rounded-lg 
			${theme === 'dark' 
			  ? 'bg-slate-800/50 border-slate-700 text-slate-200 placeholder-slate-500' 
			  : 'bg-white border-slate-200 text-slate-900 placeholder-slate-400'
			}
			border focus:outline-none focus:ring-2 focus:ring-blue-500
			transition-colors duration-200
			${readOnly ? 'bg-opacity-50 cursor-not-allowed' : ''}
		  `}
		  placeholder={placeholder}
		/>
		{value && !readOnly && (
		  <button
			onClick={() => onChange('')}
			className={`
			  absolute right-2 top-1/2 -translate-y-1/2
			  ${theme === 'dark' 
				? 'text-slate-400 hover:text-slate-300' 
				: 'text-slate-400 hover:text-slate-600'
			  }
			  focus:outline-none
			`}
		  >
			<X className="w-4 h-4" />
		  </button>
		)}
	  </div>
	);
  };


const MainField = ({
	selectedOperation,
	setSelectedOperation,
	encryptionKey,
	setEncryptionKey,
	newEncryptionKey,
	setNewEncryptionKey,
	isProcessing,
	progress,
	currentFile,
	onStartOperation,
	foundKeys,
	gameVersion,
	setGameVersion,
	selectedFolders,
	startTime,
	endTime
  }) => {
	const [errorMessage, setErrorMessage] = useState('');
	const [isButtonShaking, setIsButtonShaking] = useState('');
	const [showProgress, setShowProgress] = useState(false);

	  // 진행 상태가 변경될 때마다 showProgress 업데이트
	  React.useEffect(() => {
		if (!isProcessing) {
		  setShowProgress(false);
		}
	  }, [isProcessing]);

	const showError = (message) => {
	  setErrorMessage(message);
	  setIsButtonShaking(true);
	  setTimeout(() => {
		setErrorMessage('');
		setIsButtonShaking(false);
	  }, 3000);
	};

	const handleStartOperation = () => {
	  if (selectedFolders.length === 0) {
		showError("Please select folders first");
		return;
	  }

	  if (selectedOperation === Operation.ENCRYPT && !encryptionKey) {
		showError("Encryption key is required");
		return;
	  }

	  if (selectedOperation === Operation.REENCRYPT && !newEncryptionKey) {
		showError("New encryption key is required for re-encryption");
		return;
	  }

	  onStartOperation();
	};

	return (
		<div className="flex-1 space-y-4">
		  {/* Operation Selection */}
		  <div>
			<h2 className="text-sm font-semibold mb-3 dark:text-slate-300">Operation</h2>
			<OperationSelector
			  selectedOperation={selectedOperation}
			  onSelect={setSelectedOperation}
			/>
		  </div>

		  {/* 게임 버전과 시작 버튼 */}
		  <div className="mb-6">
			<h2 className="text-sm font-semibold mb-3 dark:text-slate-300">Game Version</h2>
			<div className="flex items-center gap-4 mb-6">
			  <div
				onClick={() => {
				  if (!(selectedOperation === Operation.FIND_KEY || selectedOperation === Operation.DECRYPT)) {
					setGameVersion(gameVersion === 'mv' ? 'mz' : 'mv');
				  }
				}}
				className={`relative flex items-center bg-slate-100 dark:bg-slate-700/80 rounded-lg p-1 w-50 h-10 cursor-pointer
				  ${(selectedOperation === Operation.FIND_KEY || selectedOperation === Operation.DECRYPT) ?
				  'opacity-50 cursor-not-allowed' : ''}`}
			  >
            {/* 슬라이딩 배경 */}
            <div
              className={`absolute h-8 w-24 bg-white dark:bg-slate-800 rounded-md shadow-sm transition-transform duration-200 ease-in-out
              ${gameVersion === 'mv' ? 'translate-x-0' : 'translate-x-24'}`}
            />

            {/* MV */}
            <div className={`w-24 flex items-center justify-center relative z-10 transition-all
              ${gameVersion === 'mv' ?
              'text-blue-600 font-semibold text-sm' :
              'text-slate-500 text-xs'}`}>
              MV
              {gameVersion === 'mv' && <span className="ml-1">▶</span>}
            </div>

            {/* MZ */}
            <div className={`w-24 flex items-center justify-center relative z-10 transition-all
              ${gameVersion === 'mz' ?
              'text-blue-600 font-semibold text-sm' :
              'text-slate-500 text-xs'}`}>
              {gameVersion === 'mz' && <span className="mr-1">◀</span>}
              MZ
            </div>
          </div>

          <div className="flex items-center gap-3">
		  <button
			onClick={handleStartOperation}
			disabled={isProcessing}
			className={`
				text-white px-6 py-2 rounded-lg
				disabled:opacity-50 disabled:cursor-not-allowed
				transition-colors duration-100
				${isButtonShaking
				? 'bg-red-600 dark:bg-red-600/50 hover:bg-red-700/50 animate-shake'
				: 'bg-blue-600 dark:bg-blue-600/50 hover:bg-blue-700/50'
				}
			`}
			>
			{isProcessing ? 'Processing...' : 'Start'}
			</button>

            {errorMessage && (
              <div className="text-red-500 text-sm animate-fade-in-out">
                {errorMessage}
              </div>
            )}
          </div>
		  </div>
		</div>
		{/* Found Keys Section */}
		{selectedOperation === Operation.FIND_KEY && (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold dark:text-slate-300">Found Keys</h2>
			<KeySlider
			foundKeys={foundKeys}
			onKeySelect={(key) => setEncryptionKey(key)}
			/>
		</div>
		)}

		{/* Key Input Fields and Progress Bar Container */}
		<div className="space-y-4">
		{!isProcessing && selectedOperation === Operation.ENCRYPT && (
			<div className="space-y-2">
			<h2 className="text-sm font-semibold dark:text-slate-300">
				Encryption Key
			</h2>
			<KeyInput
				value={encryptionKey}
				onChange={setEncryptionKey}
				placeholder="Enter encryption key"
			/>
			</div>
		)}

		{!isProcessing && selectedOperation === Operation.REENCRYPT && (
			<div className="space-y-2">
			<h2 className="text-sm font-semibold dark:text-slate-300">
				New Encryption Key
			</h2>
			<KeyInput
				value={newEncryptionKey}
				onChange={setNewEncryptionKey}
				placeholder="Enter new encryption key"
			/>
			</div>
		)}

		{/* Progress Bar */}
		{(isProcessing && selectedOperation !== Operation.FIND_KEY) && (
			<div className="mt-4">
			<ProgressBar 
				progress={progress} 
				currentFile={currentFile}
				startTime={startTime}
				endTime={endTime}
			/>
			</div>
		)}
		</div>
	  </div>
	);
  };

export default MainField;