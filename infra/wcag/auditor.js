// B33 - Auditoria de acessibilidade WCAG 2.1 AA do painel corrigido.
// Usa axe-core (mesmo motor do pa11y/Lighthouse) sobre Chromium headless, autentica
// (usuario + senha + TOTP) e audita cada tela. Saída: relatório por página + JSON.
const puppeteer = require('puppeteer-core');
const axeSource = require('axe-core').source;
const fs = require('fs');
const crypto = require('crypto');

const BASE = process.env.PAINEL_URL || 'http://10.30.2.20:8000';
const USER = process.env.USUARIO;
const SENHA = process.env.SENHA;
const SECRET = process.env.TOTP_SECRET;
const SAIDA = process.env.SAIDA || '/saida';
const CHROME = process.env.CHROME_PATH || '/usr/bin/chromium';

function base32decode(s) {
  const alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const v = alph.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totp(secret) {
  const key = base32decode(secret);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const n = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
  return (n % 1000000).toString().padStart(6, '0');
}

async function submit(page) {
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2' }).catch(() => {}),
    page.click('button[type=submit], input[type=submit], button'),
  ]);
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });
  const page = await browser.newPage();

  await page.goto(BASE + '/login', { waitUntil: 'networkidle2' });
  await page.type('[name=usuario]', USER);
  await page.type('[name=senha]', SENHA);
  await submit(page);
  if (page.url().includes('/mfa')) {
    await page.type('[name=codigo]', totp(SECRET));
    await submit(page);
  }
  const autenticado = !page.url().includes('/login') && !page.url().includes('/mfa');
  console.log('Autenticado como ' + USER + ': ' + autenticado + ' (url=' + page.url() + ')');

  const alvos = [['inicio', '/'], ['historico', '/historico'], ['usuarios', '/usuarios'],
                 ['bomba', '/bomba'], ['login', '/login'], ['mfa', '/mfa']];
  const resumo = [];
  let criticos = 0, serios = 0;

  for (const [nome, path] of alvos) {
    try {
      await page.goto(BASE + path, { waitUntil: 'networkidle2' });
      await page.evaluate(axeSource);
      const res = await page.evaluate(async () => await axe.run(document, {
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
      }));
      const imp = { critical: 0, serious: 0, moderate: 0, minor: 0 };
      for (const v of res.violations) imp[v.impact || 'minor'] += v.nodes.length;
      criticos += imp.critical; serios += imp.serious;
      resumo.push({
        nome, path, url: page.url(), violacoes: res.violations.length, impacto: imp,
        detalhe: res.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length })),
      });
    } catch (e) {
      resumo.push({ nome, path, erro: String(e) });
    }
  }
  await browser.close();

  fs.mkdirSync(SAIDA, { recursive: true });
  fs.writeFileSync(SAIDA + '/b33_wcag.json',
    JSON.stringify({ base: BASE, usuario: USER, criticos, serios, paginas: resumo }, null, 2));

  console.log('=== Auditoria WCAG 2.1 AA (axe-core) - painel corrigido ===');
  for (const p of resumo) {
    if (p.erro) { console.log(`\n[${p.nome}] ${p.path} - ERRO: ${p.erro}`); continue; }
    console.log(`\n[${p.nome}] ${p.path} - ${p.violacoes} violacoes | ` +
      `critical=${p.impacto.critical} serious=${p.impacto.serious} ` +
      `moderate=${p.impacto.moderate} minor=${p.impacto.minor}`);
    for (const d of p.detalhe) console.log(`   (${d.impact}) ${d.id}: ${d.help} [${d.nodes}]`);
  }
  console.log(`\nTOTAL: criticos=${criticos} serios=${serios}`);
  console.log(criticos === 0 && serios === 0
    ? 'RESULTADO: nenhum erro critico/serio no WCAG 2.1 AA'
    : 'RESULTADO: existem erros critical/serious a corrigir');
})().catch(e => { console.error('ERRO FATAL', e); process.exit(1); });
