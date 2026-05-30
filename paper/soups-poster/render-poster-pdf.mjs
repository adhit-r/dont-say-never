import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(__dirname, 'poster.html');
const pdfPath = path.join(__dirname, 'poster.pdf');

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1403, height: 992 },
  deviceScaleFactor: 2,
});

await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle' });
await page.pdf({
  path: pdfPath,
  format: 'A4',
  landscape: true,
  printBackground: true,
  margin: { top: '0mm', right: '0mm', bottom: '0mm', left: '0mm' },
});

await browser.close();
console.log(pdfPath);
