import React from 'react';
import { Clock, Files } from 'lucide-react';
import Modal from './Modal';

const formatDuration = (startTime, endTime) => {
	if (!startTime || !endTime) {
	  return '0.00 sec';
	}
	
	const duration = (endTime - startTime) / 1000; // 밀리초를 초로 변환
	const seconds = duration.toFixed(2);
  
	if (duration < 60) {
	  return `${seconds} sec`;
	} else {
	  const minutes = Math.floor(duration / 60);
	  const remainingSeconds = (duration % 60).toFixed(2);
	  return `${minutes} min ${remainingSeconds} sec`;
	}
  };

const ResultModal = ({ isOpen, onClose, operationName, totalFiles, startTime, endTime }) => {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Complete"
      size="sm"
    >
      <div className="space-y-6">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-12 h-12 bg-green-100 dark:bg-green-900/30 rounded-full mb-4">
            <div className="w-6 h-6 text-green-600 dark:text-green-400">✓</div>
          </div>
          <h3 className="text-lg font-medium text-slate-900 dark:text-slate-100">
            {operationName} Complete
          </h3>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-3 text-slate-600 dark:text-slate-300">
            <Files className="w-5 h-5" />
            <span>Processed Files: {totalFiles.toLocaleString()}</span>
          </div>

          <div className="flex items-center gap-3 text-slate-600 dark:text-slate-300">
            <Clock className="w-5 h-5" />
            <span>Elapsed Time: {formatDuration(startTime, endTime)}</span>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg
              hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            confirm
          </button>
        </div>
      </div>
    </Modal>
  );
};

export default ResultModal;