// SettingsContext.jsx 생성
import React, { createContext, useState, useContext, useEffect } from 'react';

const SettingsContext = createContext({
  cleanFolders: false,
  setCleanFolders: () => {},
});

export const SettingsProvider = ({ children }) => {
  const [cleanFolders, setCleanFolders] = useState(() => {
    if (typeof window === 'undefined') return false;
    return localStorage.getItem('cleanFolders') === 'true';
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    localStorage.setItem('cleanFolders', cleanFolders);
  }, [cleanFolders]);

  return (
    <SettingsContext.Provider value={{
      cleanFolders,
      setCleanFolders,
    }}>
      {children}
    </SettingsContext.Provider>
  );
};

export const useSettings = () => {
  const context = useContext(SettingsContext);
  if (context === undefined) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
};

export default SettingsContext;