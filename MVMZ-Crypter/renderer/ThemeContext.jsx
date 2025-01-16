// ThemeContext.jsx

import React, { createContext, useState, useContext, useEffect } from 'react';

export const ThemeMode = {
  LIGHT: 'light',
  DARK: 'dark',
  SYSTEM: 'system',
};

const ThemeContext = createContext({
  theme: ThemeMode.LIGHT,
  setTheme: () => {},
  resolvedTheme: ThemeMode.LIGHT,
  systemTheme: ThemeMode.LIGHT,
});

export const ThemeProvider = ({ children }) => {
  // 시스템 테마 감지
  const [systemTheme, setSystemTheme] = useState(() => {
    if (typeof window === 'undefined') return ThemeMode.LIGHT;
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? ThemeMode.DARK
      : ThemeMode.LIGHT;
  });

  // 사용자 선택 테마
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return ThemeMode.LIGHT;
    return localStorage.getItem('theme') || ThemeMode.SYSTEM;
  });

  // 실제 적용되는 테마 계산
  const resolvedTheme = theme === ThemeMode.SYSTEM ? systemTheme : theme;

  // 시스템 테마 변경 감지
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e) => {
      setSystemTheme(e.matches ? ThemeMode.DARK : ThemeMode.LIGHT);
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // 테마 변경 시 DOM 및 localStorage 업데이트
  useEffect(() => {
    if (typeof window === 'undefined') return;

    document.documentElement.setAttribute('data-theme', resolvedTheme);
    localStorage.setItem('theme', theme);
  }, [theme, resolvedTheme]);

  return (
    <ThemeContext.Provider value={{
      theme,
      setTheme,
      resolvedTheme,
      systemTheme,
    }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

export default ThemeContext;