const { app, BrowserWindow, ipcMain} = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const { execFile } = require('child_process');

// GPU 가속 비활성화
app.disableHardwareAcceleration();

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

let mainWindow;
let pythonProcess;

function createWindow() {
	// 중복 실행 방지
    const gotTheLock = app.requestSingleInstanceLock();
    if (!gotTheLock) {
        app.quit();
        return;
    }

    // 두 번째 인스턴스 실행 시 기존 창 활성화
    app.on('second-instance', (event, commandLine, workingDirectory) => {
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.focus();
        }
    });

    mainWindow = new BrowserWindow({
        width: 1024,
        height: 744,
        resizable: false,
        webPreferences: {
          nodeIntegration: false,
          contextIsolation: true,
          preload: path.join(__dirname, 'preload.js'),
          sandbox: true,
		  devTools: false
        },
        backgroundColor: '#ffffff',
        show: false,
        autoHideMenuBar: true
    });


    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

	mainWindow.setMenu(null);
	mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
    mainWindow.webContents.on('before-input-event', (event, input) => {
        if ((input.control || input.meta) && input.key.toLowerCase() === 'i') {
            event.preventDefault();
        }
    });
}

function startPythonProcess() {
	console.log('App path:', app.getAppPath());
	console.log('Resource path:', process.resourcesPath);
	
	let scriptPath;
	if (isDev) {
	  scriptPath = path.join(__dirname, 'backend', 'api.exe');
	} else {
	  scriptPath = path.join(process.resourcesPath, 'backend', 'api.exe');
	}
	
	scriptPath = scriptPath.replace(/\\/g, '/');
	console.log('Python script path:', scriptPath);
  
	// 파일 존재 여부 체크
	if (!require('fs').existsSync(scriptPath)) {
	  console.error('Python exe not found at:', scriptPath);
	  return;
	}
  
	pythonProcess = spawn(scriptPath, [], {
	  stdio: ['pipe', 'pipe', 'pipe'],
	  cwd: isDev 
		? path.dirname(__dirname)
		: path.dirname(path.dirname(process.execPath)),
	  windowsHide: false,
	  shell: true
	});
  
	pythonProcess.stdout.on('data', (data) => {
	  console.log('Python stdout:', data.toString());
	  try {
		const lines = data.toString().split('\n');
		lines.forEach(line => {
		  if (!line.trim()) return;
		  if (line.startsWith('{"type":')) {
			const message = JSON.parse(line);
			if (mainWindow && !mainWindow.isDestroyed()) {
			  mainWindow.webContents.send('python-message', message);
			}
		  }
		});
	  } catch (e) {
		console.error('Failed to parse Python output:', e);
	  }
	});
  
	pythonProcess.stderr.on('data', (data) => {
	  console.error('Python stderr:', data.toString());
	});
  
	pythonProcess.on('error', (err) => {
	  console.error('Failed to start Python process:', err);
	});
  
	pythonProcess.on('close', (code) => {
	  console.log(`Python process exited with code ${code}`);
	});
  }

// IPC 통신 처리 부분 수정
ipcMain.handle('python-command', async (event, command) => {
	try {
	  if (!pythonProcess) {
		throw new Error('Python process not running');
	  }
  
	  return new Promise((resolve, reject) => {
		// 타임아웃 설정
		const timeout = setTimeout(() => {
		  cleanup();
		  reject(new Error('Command timed out'));
		}, 300000);  // 5분
  
		// 메시지 핸들러
		const messageHandler = (data) => {
		  try {
			const lines = data.toString().split('\n');
			lines.forEach(line => {
			  if (!line.trim()) return;
			  if (line.startsWith('{"type":')) {
				const message = JSON.parse(line);
				if (message.type === 'complete') {
				  cleanup();
				  resolve(message.data);
				}
			  }
			});
		  } catch (e) {
			cleanup();
			reject(e);
		  }
		};
  
		// 에러 핸들러
		const errorHandler = (data) => {
		  cleanup();
		  reject(new Error(data.toString()));
		};
  
		// 정리 함수
		const cleanup = () => {
		  clearTimeout(timeout);
		  pythonProcess.stdout.removeListener('data', messageHandler);
		  pythonProcess.stderr.removeListener('data', errorHandler);
		};
  
		pythonProcess.stdout.on('data', messageHandler);
		pythonProcess.stderr.on('data', errorHandler);
		pythonProcess.stdin.write(JSON.stringify(command) + '\n');
	  });
	} catch (error) {
	  console.error('Python command failed:', error);
	  throw error;
	}
  });

// 앱 생명주기 이벤트 처리
app.whenReady().then(() => {
  createWindow();
  startPythonProcess();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    if (pythonProcess) {
      pythonProcess.kill();
    }
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('before-quit', () => {
  if (pythonProcess) {
    pythonProcess.kill();
  }
});