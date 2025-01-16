import React from 'react';
import { useTheme } from './ThemeContext';
import { Sun, Moon } from 'lucide-react';

const ThemeToggle = () => {
  const { theme, setTheme } = useTheme();
  
  const toggleTheme = () => {
    setTheme(theme === 'light' ? 'dark' : 'light');
  };

	// ThemeToggle.jsx 수정
	return (
		<div className="flex items-center justify-between w-full">
		<span className="text-sm text-slate-700 dark:text-slate-300">Theme</span>
		<button
			onClick={toggleTheme}
			className="relative inline-flex h-6 w-11 items-center rounded-full
					border transition-colors duration-300
					bg-slate-200 dark:bg-slate-700
					hover:bg-slate-300 dark:hover:bg-slate-600"
			role="switch"
			aria-checked={theme === 'dark'}
		>
			<span className={`${
			theme === 'dark' ? 'translate-x-6' : 'translate-x-1'
			} inline-block h-4 w-4 transform rounded-full 
			bg-white transition duration-300 ease-in-out
			flex items-center justify-center`}>
			{theme === 'dark' ? (
				<Moon className="h-3 w-3 text-slate-700" />
			) : (
				<Sun className="h-3 w-3 text-slate-700" />
			)}
			</span>
		</button>
		</div>
	);
};

export default ThemeToggle;