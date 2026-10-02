#!/usr/bin/env node
/**
 * 从 sub-store-org/Sub-Store 官方仓库同步 proxy-utils 源码
 * 只同步 parsers / preprocessors / producers 三个目录
 */
const fsp = require('node:fs/promises');
const path = require('node:path');

const REPO_ZIP = 'https://github.com/sub-store-org/Sub-Store/archive/refs/heads/master.zip';
const SOURCE_BASE = 'Sub-Store-master/backend/src/core/proxy-utils';
const TARGET_BASE = path.resolve(__dirname, 'src');
const FOLDERS = ['parsers', 'preprocessors', 'producers'];

function bufferFromArrayBuffer(ab) {
    return Buffer.from(ab);
}

(async () => {
    console.log('Downloading upstream ZIP...');
    const response = await fetch(REPO_ZIP);
    if (!response.ok) {
        throw new Error(`Download failed: HTTP ${response.status}`);
    }
    const zipBuffer = bufferFromArrayBuffer(await response.arrayBuffer());
    console.log(`Download complete (${(zipBuffer.length / 1024).toFixed(2)} KB)`);

    // 使用原生 zlib 解压 zip 太复杂，这里依赖 JSZip
    const JSZip = require('jszip');
    const zip = await JSZip.loadAsync(zipBuffer);

    console.log('');
    console.log('Checking source folders in ZIP...');
    for (const folder of FOLDERS) {
        const prefix = `${SOURCE_BASE}/${folder}/`;
        const exists = Object.keys(zip.files).some((entryName) => entryName.startsWith(prefix));
        if (!exists) {
            throw new Error(`Source folder not found: ${SOURCE_BASE}/${folder}`);
        }
        console.log(`  ✓ ${folder}`);
    }

    console.log('');
    console.log('Removing local target folders...');
    for (const folder of FOLDERS) {
        const targetPath = path.join(TARGET_BASE, 'core/proxy-utils', folder);
        await fsp.rm(targetPath, { recursive: true, force: true });
        console.log(`  ✓ Removed: ${folder}`);
    }

    console.log('');
    console.log('Extracting...');
    const sourcePrefix = `${SOURCE_BASE}/`;
    for (const [entryName, entry] of Object.entries(zip.files)) {
        if (entry.dir || !entryName.startsWith(sourcePrefix)) {
            continue;
        }
        const relativePath = entryName.slice(sourcePrefix.length);
        const [folder] = relativePath.split('/');
        if (!FOLDERS.includes(folder)) {
            continue;
        }
        const targetPath = path.join(TARGET_BASE, 'core/proxy-utils', relativePath);
        await fsp.mkdir(path.dirname(targetPath), { recursive: true });
        const data = await entry.async('nodebuffer');
        await fsp.writeFile(targetPath, data);
        console.log(`  ✓ ${relativePath}`);
    }

    console.log('');
    console.log('Sync complete.');
})().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
});
