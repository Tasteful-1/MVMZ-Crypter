const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('mvmz', {
  sendCommand: (command) => {
    return ipcRenderer.invoke('python-command', command);
  },
  
  onMessage: (callback) => {
    const wrappedCallback = (event, message) => callback(message);
    ipcRenderer.on('python-message', wrappedCallback);
    return () => ipcRenderer.removeListener('python-message', wrappedCallback);
  },
  
  removeListeners: () => {
    ipcRenderer.removeAllListeners('python-message');
  }
});