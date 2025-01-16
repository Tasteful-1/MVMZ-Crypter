import React, { useState, useRef, useEffect } from 'react';
import { Settings, ChevronRight } from 'lucide-react';
import ThemeToggle from './ThemeToggle';
import Modal from './Modal';
import { useSettings } from './SettingsContext';

const ToggleSwitch = ({ checked, onChange }) => (
  <button
    onClick={onChange}
    className={`
      relative inline-flex h-6 w-11 items-center rounded-full
      transition-colors duration-300 ease-in-out focus:outline-none
      ${checked
        ? 'bg-blue-600'
        : 'bg-slate-200 dark:bg-slate-700'
      }
    `}
    role="switch"
    aria-checked={checked}
  >
    <span
      className={`
        inline-block h-4 w-4 transform rounded-full
        transition-transform duration-200 ease-in-out
        ${checked
          ? 'translate-x-6 bg-white'
          : 'translate-x-1 bg-gray-400'
        }
      `}
    />
  </button>
);

const SettingsMenu = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [modalConfig, setModalConfig] = useState({ isOpen: false, title: '', content: '' });
  const menuRef = useRef(null);
  const { cleanFolders, setCleanFolders } = useSettings();

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const menuItems = [
    {
      type: 'component',
      component: ThemeToggle
    },
    {
      type: 'toggle',
      label: 'Clean Output Folders',
      checked: cleanFolders,
      onChange: () => setCleanFolders(!cleanFolders),
      description: 'Delete existing same named folders before processing'
    },
    {
      type: 'divider'
    },
    {
      type: 'button',
      label: 'About',
      onClick: () => {
        setModalConfig({
          isOpen: true,
		  size: 'sm',
          title: 'About',
          content: 'MVMZ-Crypter\nDeveloped for RPG Maker MV/MZ'
        });
      }
    },
    {
      type: 'button',
      label: 'License',
      onClick: () => {
        setModalConfig({
          isOpen: true,
		  size: 'lg',
          title: 'License',
          content: 'MIT License\n\nCopyright (c) 2025 Tasteful-1\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'
        });
      }
    },
	{
      type: 'button',
      label: 'References',
      onClick: () => {
        setModalConfig({
          isOpen: true,
		  size: 'md',
          title: 'References',
          content: '◈ RPG-Maker-MV-Decrypter\n　MIT License\n　Copyright (c) 2016 Peter Dragicevic'
        });
      }
    }
  ];

  return (
    <div ref={menuRef} className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="p-2 rounded-full hover:bg-slate-700 transition-colors focus:outline-none"
        title="Settings"
      >
        <Settings className="w-5 h-5 text-white" />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-64 rounded-lg bg-white dark:bg-slate-800 shadow-lg border border-slate-200 dark:border-slate-700 py-1 z-50">
          {menuItems.map((item, index) => {
            if (item.type === 'divider') {
              return <div key={index} className="my-1 border-t border-slate-200 dark:border-slate-700" />;
            }

            if (item.type === 'component') {
              const Component = item.component;
              return (
                <div key={index} className="px-4 py-2">
                  <Component />
                </div>
              );
            }

            if (item.type === 'toggle') {
              return (
                <div key={index} className="px-4 py-2">
                  <div className="flex items-center justify-between">
                    <div className="max-w-[160px]">
                      <div className="text-sm text-slate-700 dark:text-slate-300">
                        {item.label}
                      </div>
                      {item.description && (
                        <div className="text-xs text-slate-500 dark:text-slate-400">
                          {item.description}
                        </div>
                      )}
                    </div>
                    <ToggleSwitch
                      checked={item.checked}
                      onChange={item.onChange}
                    />
                  </div>
                </div>
              );
            }

            return (
              <button
                key={index}
                onClick={() => {
                  item.onClick();
                  setIsOpen(false);
                }}
                className="w-full px-4 py-2 text-left text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700/50 flex items-center justify-between"
              >
                {item.label}
                <ChevronRight className="w-4 h-4 text-slate-400" />
              </button>
            );
          })}
        </div>
      )}

      <Modal
        isOpen={modalConfig.isOpen}
		size={modalConfig.size}
        onClose={() => setModalConfig({ ...modalConfig, isOpen: false })}
        title={modalConfig.title}
      >
        <p className="text-slate-600 dark:text-slate-300 whitespace-pre-line">
          {modalConfig.content}
        </p>
      </Modal>
    </div>
  );
};

export default SettingsMenu;