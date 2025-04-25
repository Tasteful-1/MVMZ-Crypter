// Modal.jsx
import React from 'react';
import { X } from 'lucide-react';

const Modal = ({ isOpen, onClose, title, children, size }) => {
  if (!isOpen) return null;

  // 모달 크기별 스타일 매핑
  const sizeStyles = {
    sm: 'max-w-[400px]',  // About 모달용
    md: 'max-w-[600px]',  // References 모달용
    lg: 'max-w-[800px]'   // License 모달용
  };

  return (
    <div className="fixed inset-0 z-50 overflow-auto bg-black/50 flex items-center justify-center p-4">
      <div className={`
        relative w-full bg-white dark:bg-slate-800 rounded-lg shadow-xl
        ${sizeStyles[size] || sizeStyles.md}
        transform transition-all duration-300 ease-in-out
      `}>
        {/* 모달 헤더 */}
        <div className="flex items-center justify-between p-4 border-b dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            {title}
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-500 dark:hover:text-slate-300
              transition-colors duration-200"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* 모달 컨텐츠 */}
        <div className="p-4 overflow-y-auto max-h-[calc(100vh-10rem)]">
          <div className="prose dark:prose-invert max-w-none">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Modal;