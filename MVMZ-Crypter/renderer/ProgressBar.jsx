import React, { useState, useEffect } from 'react';

const ProgressBar = ({ currentFile, startTime, endTime }) => {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    let timerId;

    const updateTime = () => {
      if (!startTime) return;
      
      const now = endTime || Date.now();
      const elapsed = Math.floor((now - startTime) / 1000);
      setElapsedSeconds(elapsed);
    };

    if (startTime) {
      // 즉시 첫 업데이트
      updateTime();

      // 작업 중일 때만 타이머 시작
      if (!endTime) {
        timerId = setInterval(updateTime, 1000);
      }
    }

    return () => {
      if (timerId) {
        clearInterval(timerId);
      }
    };
  }, [startTime, endTime]);

  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const isComplete = endTime;

  return (
    <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 h-24 flex items-center justify-center select-none">
      <div className="w-full text-center space-y-2">
        <div className="text-slate-600 dark:text-slate-300">
          {isComplete ? "Operation completed" : "Processing..."}
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
          {formatTime(elapsedSeconds)}
        </div>
        {currentFile && (
          <div className="text-xs text-slate-500 dark:text-slate-400 truncate px-2">
            {currentFile}
          </div>
        )}
      </div>
    </div>
  );
};

export default ProgressBar;