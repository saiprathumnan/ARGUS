// Scripted end-to-end UI check (headless Chrome). Needs both servers running and: npm i --no-save puppeteer-core
// Run from frontend/:  mkdir -p ui-flow-output && CHROME=/path/to/chrome node scripts/ui-flow.cjs
const puppeteer = require('puppeteer-core');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox', '--use-angle=swiftshader', '--use-gl=angle', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });
  const errors = []; const log = (...a) => console.log(...a);
  page.on('console', (m) => { if (m.type() === 'error' && !/404|Failed to load resource/.test(m.text())) errors.push(m.text().slice(0, 240)); });
  page.on('pageerror', (e) => errors.push('PAGEERROR ' + String(e).slice(0, 240)));
  const go = async (u) => { await page.goto('http://localhost:3000' + u, { waitUntil: 'domcontentloaded' }); await sleep(1800); };
  const text = () => page.evaluate(() => document.body.innerText);
  const clickText = (sel, t) => page.evaluate((sel, t) => { const el = [...document.querySelectorAll(sel)].find((e) => e.textContent.trim().toLowerCase().includes(t.toLowerCase())); if (el) el.click(); return !!el; }, sel, t);

  // 1. create a case through the form
  await go('/new');
  log('launch disabled before input:', await page.$eval('button.btn-primary', (b) => b.disabled));
  await page.type('input[placeholder^="e.g."]', 'UI flow test: reported invoice email');
  await page.type('input[aria-label="Suspicious URL"]', 'http://paypa1.com.account-verify.example/signin/update-billing?session=1');
  await clickText('button', 'Add URL');
  const fi = await page.$('input[type=file]');
  await fi.uploadFile(require('path').resolve('../backend/data/samples/phishing_email.eml'), require('path').resolve('../backend/data/samples/workstation_capture.pcap'));
  await sleep(400);
  await page.screenshot({ path: './ui-flow-output/new-staged.png' });
  await clickText('button', 'Create case and start analysis');
  await page.waitForFunction(() => location.pathname.startsWith('/i/'), { timeout: 30000 });
  const inv = await page.evaluate(() => location.pathname.split('/')[2]);
  await sleep(700);
  await page.screenshot({ path: './ui-flow-output/workspace-live.png' });
  log('created', inv, '| live stage text:', (await text()).match(/(EVIDENCE COLLECTION|PROCESSING|CORRELATION|VERIFICATION|COMPLETED)/g)?.slice(0, 3));
  await page.waitForFunction(() => document.body.innerText.includes('OPEN DOSSIER'), { timeout: 60000 });
  log('completed; verdict shown:', /Suspicious/.test(await text()));
  log('rejected upload handling: ', await (async () => { await go('/new'); await page.type('input[placeholder^="e.g."]', 'bad'); const f2 = await page.$('input[type=file]'); require('fs').writeFileSync('./ui-flow-output/empty.bin', ''); await f2.uploadFile('./ui-flow-output/empty.bin'); await sleep(300); await clickText('button', 'Create case and start analysis'); await sleep(2500); return (await text()).match(/No evidence was accepted[^.]*\./)?.[0] || (await text()).match(/empty[^\n]*/i)?.[0]; })());

  // 2. command palette search
  await go(`/i/${inv}`);
  await page.keyboard.down('Control'); await page.keyboard.press('k'); await page.keyboard.up('Control');
  await sleep(300); await page.keyboard.type('paypa1-secure'); await sleep(1200);
  await page.screenshot({ path: './ui-flow-output/palette.png' });
  log('palette results:', await page.$$eval('[role=option]', (o) => o.length));
  await page.keyboard.press('Enter'); await sleep(2500);
  log('palette navigated to:', await page.evaluate(() => location.pathname + location.search.slice(0, 40)));
  log('shortcut g t ->', await (async () => { await page.keyboard.press('Escape'); await page.keyboard.press('g'); await page.keyboard.press('t'); await sleep(1500); return page.evaluate(() => location.pathname); })());

  // 3. universe interactions
  await go(`/i/${inv}/universe`);
  await sleep(1500);
  const before = (await text()).match(/(\d+) \/ (\d+) ENTITIES/);
  await page.evaluate(() => { const b = [...document.querySelectorAll('ul button')].find((x) => /high|critical/i.test(x.textContent)); b && b.click(); });
  await sleep(1500);
  log('inspector opened:', /CONNECTED ENTITIES/.test(await text()));
  await clickText('button', 'Isolate'); await sleep(800);
  const iso = (await text()).match(/(\d+) \/ (\d+) ENTITIES/);
  log('entities before/after isolate:', before?.[0], '->', iso?.[0]);
  await page.screenshot({ path: './ui-flow-output/universe-isolated.png' });
  await clickText('button', 'Exit isolation'); await sleep(400);
  await clickText('button', 'IP address'); await sleep(500);
  log('after hiding IPs:', (await text()).match(/(\d+) \/ (\d+) ENTITIES/)?.[0]);
  await clickText('button', 'IP address');
  await page.select('select', 'high'); await sleep(500);
  log('min severity high:', (await text()).match(/(\d+) \/ (\d+) ENTITIES/)?.[0]);
  await page.select('select', 'info');
  await page.$eval('input[type=range]', (el) => { const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set; set.call(el, '300'); el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); });
  await sleep(600);
  log('time cutoff 30%:', (await text()).match(/(\d+) \/ (\d+) ENTITIES/)?.[0], (await text()).match(/≤ [\d\- :]+/)?.[0]);
  await clickText('button', 'Temporal depth'); await sleep(1500);
  await page.screenshot({ path: './ui-flow-output/universe-time.png' });
  // click directly on the WebGL canvas centre to test picking does not throw
  const cv = await page.$('canvas'); const box = await cv.boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2); await sleep(500);

  // 4. timeline
  await go(`/i/${inv}/timeline`); await sleep(2000);
  await page.screenshot({ path: './ui-flow-output/timeline.png' });
  await page.evaluate(() => document.querySelector('ol[class] li button, ol li button')?.click());
  await page.evaluate(() => { const items = [...document.querySelectorAll('ol li button')]; items.find((b) => /EMAIL/.test(b.textContent))?.click(); });
  await sleep(700);
  log('event panel:', /TIME BASIS/.test(await text()), '| basis label:', (await text()).match(/timestamp recorded in the evidence/)?.[0]);
  await page.evaluate(() => document.querySelector('button[aria-label="Play timeline"]')?.click()); await sleep(1500);
  log('playhead moved:', await page.$eval('input[type=range]', (e) => e.value));
  await page.evaluate(() => document.querySelector('button[aria-label="Pause"]')?.click());
  await page.screenshot({ path: './ui-flow-output/timeline-playing.png' });
  await clickText('button[role=radio]', '2D'); await sleep(800);
  log('2D swimlane svg rects:', await page.$$eval('svg[aria-label="Incident timeline swimlanes"] rect', (r) => r.length));
  await page.screenshot({ path: './ui-flow-output/timeline-2d.png' });
  await clickText('button[role=radio]', '3D');

  // 5. lab tabs
  await go(`/i/${inv}/lab`);
  await clickText('button[role=radio]', 'ATT&CK'); await sleep(600); await page.screenshot({ path: './ui-flow-output/lab-attack.png' });
  log('attack techniques shown:', (await text()).match(/T\d{4}(\.\d{3})?/g)?.length);
  await clickText('button[role=radio]', 'Models'); await sleep(800); await page.screenshot({ path: './ui-flow-output/lab-models.png' });
  log('models tab shows confusion matrix:', /TRUE POSITIVE/i.test(await text()));

  // 6. dossier print layout -> real PDF
  await go(`/i/${inv}/dossier`); await sleep(1200);
  await page.pdf({ path: './ui-flow-output/dossier.pdf', format: 'A4', printBackground: true });
  log('dossier pdf bytes:', require('fs').statSync('./ui-flow-output/dossier.pdf').size);

  // 7. error + empty states, responsive, reduced motion
  await go('/i/INV-000000000000'); log('missing case:', (await text()).match(/Not found|investigation not found/gi));
  await go('/does-not-exist'); log('404 page:', /does not exist/.test(await text()));
  await page.setViewport({ width: 390, height: 844 }); await go(`/i/${inv}`); await sleep(1200); await page.screenshot({ path: './ui-flow-output/mobile-workspace.png', fullPage: false });
  log('mobile horizontal overflow px:', await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth));
  await go(`/i/${inv}/universe`); await sleep(1200); await page.screenshot({ path: './ui-flow-output/mobile-universe.png' });
  log('mobile universe overflow px:', await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth));
  await page.setViewport({ width: 1440, height: 900 });
  await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]); await go('/'); await sleep(1000);
  log('reduced motion landing canvas present:', !!(await page.$('canvas')));
  log('CONSOLE ERRORS', JSON.stringify([...new Set(errors)], null, 1));
  require('fs').writeFileSync('./ui-flow-output/inv', inv);
  await browser.close();
})().catch((e) => { console.error('FLOW FAILED', e); process.exit(1); });
