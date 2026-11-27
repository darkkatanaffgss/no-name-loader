const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  minimize: () => ipcRenderer.send('window:minimize'),
  close: () => ipcRenderer.send('window:close'),
  openExternal: (url) => ipcRenderer.send('shell:open-external', url),
  getDeviceInfo: () => ipcRenderer.invoke('auth:get-device-info'),
  verifyLicense: (key) => ipcRenderer.invoke('auth:verify-key', key),
  logout: () => ipcRenderer.invoke('auth:logout'),
  launchSoftware: (payload) => ipcRenderer.invoke('software:launch', payload),
  onSessionInvalidated: (cb) => ipcRenderer.on('auth:session-invalidated', (_e, reason) => cb(reason))
});
