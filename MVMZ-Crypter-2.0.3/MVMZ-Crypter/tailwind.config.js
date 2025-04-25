/** @type {import('tailwindcss').Config} */
module.exports = {
	content: [
	  "./renderer/**/*.{js,jsx,ts,tsx}",
	],
	darkMode: ['class', '[data-theme="dark"]'],
	theme: {
	  extend: {
		colors: {
		  // 기본 배경 색상
		  background: {
			DEFAULT: 'var(--background)',
			secondary: 'var(--background-secondary)',
		  },
		  // 전경(텍스트, 아이콘 등) 색상
		  foreground: {
			DEFAULT: 'var(--foreground)',
			secondary: 'var(--foreground-secondary)',
			muted: 'var(--foreground-muted)',
		  },
		  // 강조 색상
		  accent: {
			DEFAULT: 'var(--accent)',
			hover: 'var(--accent-hover)',
		  },
		  // 테두리 색상
		  border: {
			DEFAULT: 'var(--border)',
			hover: 'var(--border-hover)',
		  },
		},
	  },
	},
	theme: {
	extend: {
		keyframes: {
		shake: {
			'0%, 100%': { transform: 'translateX(0)' },
			'25%': { transform: 'translateX(-4px)' },
			'75%': { transform: 'translateX(4px)' },
		},
		'fade-in-out': {
			'0%': { opacity: '0' },
			'10%': { opacity: '1' },
			'90%': { opacity: '1' },
			'100%': { opacity: '0' },
		}
		},
		animation: {
		shake: 'shake 0.2s ease-in-out 3',
		'fade-in-out': 'fade-in-out 3s ease-in-out',
		}
	  }
	},
plugins: [],
}