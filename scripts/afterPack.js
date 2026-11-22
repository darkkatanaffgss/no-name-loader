const path = require('path');

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;

  const { rcedit } = await import('rcedit');
  const rootDir = context.packager.projectDir;
  const exePath = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.exe`);
  const iconPath = path.join(rootDir, 'assets', 'icon.ico');

  console.log('      [afterPack] Embedding NN icon & metadata via rcedit...');
  await rcedit(exePath, {
    icon: iconPath,
    'version-string': {
      CompanyName: 'no name',
      FileDescription: 'no name Loader',
      OriginalFilename: 'no name.exe',
      ProductName: 'no name'
    },
    'file-version': '1.0.0',
    'product-version': '1.0.0'
  });
};
