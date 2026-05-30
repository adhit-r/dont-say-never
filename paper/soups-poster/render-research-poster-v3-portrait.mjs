import { chromium } from 'playwright';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(__dirname, 'research-poster-v3-portrait.html');
const pdfPath = path.join(__dirname, 'research-poster-v3-portrait.pdf');
const pngPath = path.join(__dirname, 'research-poster-v3-portrait.png');

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1587, height: 2245 },
  deviceScaleFactor: 2,
});

await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle' });
await page.pdf({
  path: pdfPath,
  format: 'A4',
  landscape: false,
  printBackground: true,
  margin: { top: 0, right: 0, bottom: 0, left: 0 },
});
await page.screenshot({ path: pngPath, fullPage: true });

await browser.close();
console.log(`Wrote ${pdfPath}`);
console.log(`Wrote ${pngPath}`);
