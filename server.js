const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
let D = { users: {}, cars: [], sessions: {} };
try { D = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const save = () => fs.writeFileSync(FILE, JSON.stringify(D));
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');

function mkUser(name, pass, owner) {
  const salt = crypto.randomBytes(8).toString('hex');
  D.users[name.toLowerCase()] = { name, salt, h: hash(pass, salt), coins: 1000, owner: !!owner, note: '' };
}
const OU = process.env.OWNER_USER, OP = process.env.OWNER_PASS;
if (OU && OP && !D.users[OU.toLowerCase()]) { mkUser(OU, OP, true); save(); }

function cookie(req, k) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(k + '='));
  return m ? m.slice(k.length + 1) : null;
}
function auth(req, res, next) {
  const key = D.sessions[cookie(req, 't')];
  if (!key || !D.users[key]) return res.status(401).json({ error: 'سجّل الدخول' });
  req.key = key; req.u = D.users[key]; next();
}
function owner(req, res, next) { if (!req.u.owner) return res.status(403).json({ error: 'للمالك فقط' }); next(); }
function login(res, key) {
  const t = crypto.randomBytes(24).toString('hex');
  D.sessions[t] = key; save();
  res.setHeader('Set-Cookie', `t=${t}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`);
}
const int = v => Number.isInteger(v) && v > 0 ? v : null;

app.post('/api/register', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 16), pass = String(req.body.pass || '');
  if (name.length < 2 || pass.length < 4) return res.status(400).json({ error: 'الاسم حرفان على الأقل وكلمة السر 4 أحرف' });
  const key = name.toLowerCase();
  if (D.users[key]) return res.status(400).json({ error: 'الاسم مستخدم' });
  mkUser(name, pass, false); login(res, key); res.json({ ok: 1 });
});
app.post('/api/login', (req, res) => {
  const key = String(req.body.name || '').trim().toLowerCase(), u = D.users[key];
  if (!u) return res.status(400).json({ error: 'بيانات خاطئة' });
  const a = Buffer.from(hash(String(req.body.pass || ''), u.salt)), b = Buffer.from(u.h);
  if (!crypto.timingSafeEqual(a, b)) return res.status(400).json({ error: 'بيانات خاطئة' });
  login(res, key); res.json({ ok: 1 });
});
app.post('/api/logout', (req, res) => { delete D.sessions[cookie(req, 't')]; save(); res.json({ ok: 1 }); });

app.get('/api/state', auth, (req, res) => {
  const all = Object.entries(D.users).map(([k, u]) => ({ key: k, name: u.name, coins: u.coins }));
  res.json({
    me: { name: req.u.name, coins: req.u.coins, note: req.u.note, owner: req.u.owner },
    board: all.filter(p => !D.users[p.key].owner).sort((a, b) => b.coins - a.coins).slice(0, 10),
    players: req.u.owner ? all.filter(p => !D.users[p.key].owner) : undefined,
    cars: D.cars
  });
});
app.post('/api/ack', auth, (req, res) => { req.u.note = ''; save(); res.json({ ok: 1 }); });

app.post('/api/bet', auth, (req, res) => {
  const s = int(req.body.stake);
  if (!s || s > req.u.coins) return res.status(400).json({ error: 'المبلغ غير صحيح' });
  const win = crypto.randomInt(100) < 47;
  req.u.coins += win ? s : -s; save();
  res.json({ win, coins: req.u.coins });
});
app.post('/api/buy', auth, (req, res) => {
  const c = D.cars.find(x => x.id === req.body.id);
  if (!c || c.soldTo) return res.status(400).json({ error: 'غير متاحة' });
  if (req.u.coins < c.price) return res.status(400).json({ error: 'رصيدك لا يكفي' });
  req.u.coins -= c.price; c.soldTo = req.u.name; save(); res.json({ ok: 1 });
});

app.post('/api/admin/car', auth, owner, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40), price = int(req.body.price);
  if (!name || !price) return res.status(400).json({ error: 'بيانات ناقصة' });
  D.cars.push({ id: crypto.randomBytes(4).toString('hex'), name, price, soldTo: null }); save(); res.json({ ok: 1 });
});
app.delete('/api/admin/car/:id', auth, owner, (req, res) => {
  D.cars = D.cars.filter(c => c.id !== req.params.id); save(); res.json({ ok: 1 });
});
app.post('/api/admin/adjust', auth, owner, (req, res) => {
  const p = D.users[req.body.key], a = int(req.body.amount);
  if (!p || p.owner || !a) return res.status(400).json({ error: 'بيانات خاطئة' });
  const fine = req.body.type === 'fine', why = String(req.body.reason || '').slice(0, 100);
  p.coins = Math.max(0, p.coins + (fine ? -a : a));
  if (fine) p.note = `تم خصم ${a} عملة${why ? ': ' + why : ''}`;
  save(); res.json({ ok: 1 });
});

app.listen(process.env.PORT || 3000, () => console.log('One X City is running'));
