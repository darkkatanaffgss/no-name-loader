const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const JavaScriptObfuscator = require('javascript-obfuscator');

function copyDirRecursive(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dst, entry.name);
    if (entry.isDirectory()) {
      copyDirRecursive(s, d);
    } else {
      fs.copyFileSync(s, d);
    }
  }
}

function obfuscateFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const result = JavaScriptObfuscator.obfuscate(raw, {
    compact: true,
    controlFlowFlattening: false,
    deadCodeInjection: false,
    identifierNamesGenerator: 'hexadecimal',
    renameGlobals: false,
    selfDefending: false,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 0.75,
    unicodeEscapeSequence: false
  });
  fs.writeFileSync(filePath, result.getObfuscatedCode(), 'utf8');
}

async function build() {
  const rootDir = path.resolve(__dirname, '..');
  const stageDir = path.join(rootDir, 'build-stage');

  console.log('\n================================================');
  console.log('  no name — Hardened Single-File EXE Builder');
  console.log('================================================\n');

  console.log('[1/5] Checking assets and core files...');
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

  console.log('[2/5] Preparing staging directory & obfuscating release JS...');
  if (fs.existsSync(stageDir)) {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
  fs.mkdirSync(stageDir, { recursive: true });

  // Copy app files into build-stage (keeps original repo source clean and readable)
  for (const file of ['package.json', 'main.js', 'preload.js', 'index.html', 'styles.css', 'renderer.js']) {
    fs.copyFileSync(path.join(rootDir, file), path.join(stageDir, file));
  }
  copyDirRecursive(path.join(rootDir, 'assets'), path.join(stageDir, 'assets'));
  copyDirRecursive(path.join(rootDir, 'sdk'), path.join(stageDir, 'sdk'));
  copyDirRecursive(path.join(rootDir, 'scripts'), path.join(stageDir, 'scripts'));

  for (const jsFile of ['main.js', 'preload.js', 'renderer.js', 'sdk/loader-sdk.js']) {
    obfuscateFile(path.join(stageDir, jsFile));
  }

  // Generate SHA-256 runtime integrity manifest over staged files
  const integrityTargets = ['index.html', 'styles.css', 'renderer.js', 'preload.js', 'sdk/loader-sdk.js'];
  const manifest = {};
  for (const rel of integrityTargets) {
    manifest[rel] = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(stageDir, rel)))
      .digest('hex');
  }
  fs.writeFileSync(path.join(stageDir, 'integrity.json'), JSON.stringify(manifest, null, 2), 'utf8');
  console.log('      Obfuscation + SHA-256 integrity manifest complete.');

  console.log('[3/5] Preparing output directory...');
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

  console.log('[4/5] Building ASAR + Single-File Portable EXE...');
  try {
    execSync(`npx electron-builder --win portable --projectDir="${stageDir}" --config.directories.output="${outDir}"`, {
      cwd: rootDir,
      stdio: 'inherit',
      env: {
        ...process.env,
        CSC_IDENTITY_AUTO_DISCOVERY: 'false'
      }
    });
  } finally {
    if (fs.existsSync(stageDir)) {
      fs.rmSync(stageDir, { recursive: true, force: true });
    }
  }

  const portableExe = path.join(outDir, 'no name.exe');
  if (!fs.existsSync(portableExe)) {
    throw new Error(`Portable executable was not created at ${outDirName}/no name.exe`);
  }

  console.log('[5/5] Verifying single-file EXE & cleaning extra DLL folder...');
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
