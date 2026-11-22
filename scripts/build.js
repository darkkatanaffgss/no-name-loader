const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

async function build() {
  const rootDir = path.resolve(__dirname, '..');

  console.log('\n================================================');
  console.log('  no name — Single-File Portable EXE Builder');
  console.log('================================================\n');

  console.log('[1/4] Checking assets and core files...');
  const required = [
    'assets/icon.ico',
    'assets/icon.png',
    'assets/cs2.png',
    'assets/csgo.png',
    'assets/minecraft.png',
    'assets/banner-cs2.jpg',
    'assets/banner-csgo.jpg',
    'assets/banner-minecraft.jpg',
    'sdk/loader-sdk.js',
    'main.js',
    'preload.js',
    'index.html',
    'styles.css',
    'renderer.js'
  ];
  for (const rel of required) {
    if (!fs.existsSync(path.join(rootDir, rel))) {
      throw new Error(`Missing required file: ${rel}`);
    }
  }
  console.log('      All assets & source files verified.');

  console.log('[2/4] Preparing output directory...');
  const candidates = ['release', 'release-latest', 'release-v2', `release-${Date.now()}`];
  let outDirName = null;
  let outDir = null;
  for (const name of candidates) {
    const dir = path.join(rootDir, name);
    try {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
      outDirName = name;
      outDir = dir;
      break;
    } catch (err) {
      if (err.code === 'EPERM' || err.code === 'EBUSY') {
        console.log(`      ${name}/no name.exe is currently open -> trying next folder...`);
        continue;
      }
      throw err;
    }
  }

  console.log('[3/4] Building ASAR + Single-File Portable EXE...');
  execSync(`npx electron-builder --win portable --config.directories.output=${outDirName}`, {
    cwd: rootDir,
    stdio: 'inherit',
    env: {
      ...process.env,
      CSC_IDENTITY_AUTO_DISCOVERY: 'false'
    }
  });

  const portableExe = path.join(outDir, 'no name.exe');
  if (!fs.existsSync(portableExe)) {
    throw new Error(`Portable executable was not created at ${outDirName}/no name.exe`);
  }

  console.log('[4/4] Verifying single-file EXE & cleaning extra DLL folder...');
  const sizeBytes = fs.statSync(portableExe).size;
  if (sizeBytes < 20 * 1024 * 1024) {
    throw new Error(`Unexpectedly small portable EXE (${sizeBytes} bytes) — build may be incomplete.`);
  }

  for (const entry of fs.readdirSync(outDir)) {
    if (entry !== 'no name.exe') {
      fs.rmSync(path.join(outDir, entry), { recursive: true, force: true });
    }
  }

  const sizeMb = (sizeBytes / (1024 * 1024)).toFixed(1);
  console.log('\nBuild completed cleanly!');
  console.log(`  Single EXE : ${portableExe} (${sizeMb} MB)`);
  console.log('  Loose DLLs : 0\n');
}

build().catch((err) => {
  console.error('\nBuild failed:', err);
  process.exit(1);
});
