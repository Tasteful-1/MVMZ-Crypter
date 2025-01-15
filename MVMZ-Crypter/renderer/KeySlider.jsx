import React, { useState, useRef, useEffect } from 'react';
import { Copy, ChevronLeft, ChevronRight } from 'lucide-react';
import { useTheme } from './ThemeContext';  // ThemeContext import 추가

const CopyButton = ({ text }) => {
  // CopyButton 컴포넌트 코드는 그대로 유지
  const [tooltipText, setTooltipText] = useState('');
  const tooltipTimeoutRef = useRef(null);
  const mouseEnterTimeoutRef = useRef(null);

  const showTooltip = (text) => {
    setTooltipText(text);
    if (tooltipTimeoutRef.current) {
      clearTimeout(tooltipTimeoutRef.current);
    }
  };

  const hideTooltip = () => {
    tooltipTimeoutRef.current = setTimeout(() => {
      setTooltipText('');
    }, 1000);
  };

  const handleMouseEnter = () => {
    mouseEnterTimeoutRef.current = setTimeout(() => {
      showTooltip('Copy');
    }, 1000);
  };

  const handleMouseLeave = () => {
    if (mouseEnterTimeoutRef.current) {
      clearTimeout(mouseEnterTimeoutRef.current);
    }
    hideTooltip();
  };

  const handleClick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      showTooltip('Copied!');
      hideTooltip();
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  useEffect(() => {
    return () => {
      if (tooltipTimeoutRef.current) clearTimeout(tooltipTimeoutRef.current);
      if (mouseEnterTimeoutRef.current) clearTimeout(mouseEnterTimeoutRef.current);
    };
  }, []);

  return (
    <button
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
      className="relative p-1 rounded-md hover:bg-slate-100 text-slate-400 hover:text-slate-600 transition-colors"
    >
      <Copy className="w-4 h-4" />
      {tooltipText && (
        <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-slate-800 text-white text-xs px-2 py-1 rounded">
          {tooltipText}
        </div>
      )}
    </button>
  );
};

export const KeySlider = ({ foundKeys = new Map(), onKeySelect }) => {
  const { theme } = useTheme();  // useTheme hook 사용
  const [currentIndex, setCurrentIndex] = React.useState(0);
  const keyList = React.useMemo(() => Array.from(foundKeys.entries()), [foundKeys]);
  
  React.useEffect(() => {
    if (keyList.length > 0 && onKeySelect) {
      onKeySelect(keyList[currentIndex][0]);
    }
  }, [currentIndex, keyList, onKeySelect]);

  if (keyList.length === 0) {
    return (
      <div className="bg-slate-50 dark:bg-slate-900 rounded-lg p-3 h-32 flex items-center justify-center select-none">
        <div className="text-sm text-slate-500 text-center">
          No keys found yet. Click Start to begin searching.
        </div>
      </div>
    );
  }

  const [currentKey, currentFolders] = keyList[currentIndex];

  return (
    <div className={`relative bg-white dark:bg-slate-800 rounded-lg p-3 h-32
    ${theme === 'dark' ? 'border border-slate-700' : 'shadow-sm'}`}>
      <div className="bg-white dark:bg-slate-900 p-3 rounded border border-slate-200 dark:border-slate-700 h-full select-none">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <code className="text-sm text-slate-800 dark:text-slate-200 font-mono select-text">
              {currentKey}
            </code>
            <CopyButton text={currentKey} />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {currentFolders.length} folder{currentFolders.length !== 1 ? 's' : ''}
            </span>
            {keyList.length > 1 && (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setCurrentIndex(prev => 
                    prev > 0 ? prev - 1 : keyList.length - 1
                  )}
                  className="p-1 hover:bg-slate-100 dark:hover:bg-slate-700 rounded transition-colors"
                >
                  <ChevronLeft className="w-4 h-4 text-slate-600 dark:text-slate-400" />
                </button>
                <button
                  onClick={() => setCurrentIndex(prev => 
                    prev < keyList.length - 1 ? prev + 1 : 0
                  )}
                  className="p-1 hover:bg-slate-100 dark:hover:bg-slate-700 rounded transition-colors"
                >
                  <ChevronRight className="w-4 h-4 text-slate-600 dark:text-slate-400" />
                </button>
              </div>
            )}
          </div>
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400 overflow-y-auto max-h-12">
          {currentFolders.join(', ')}
        </div>
      </div>

      {keyList.length > 1 && (
        <div className="absolute bottom-5 left-1/2 transform -translate-x-1/2 flex gap-1">
          {keyList.map((_, index) => (
            <div
              key={index}
              className={`w-1.5 h-1.5 rounded-full transition-colors 
                ${index === currentIndex ? 'bg-blue-600' : 'bg-slate-300'}`}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default KeySlider;