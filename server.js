const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const pool = require('./db/db');
require('dotenv').config();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
const PORT=process.env.PORT||3000;
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    secret: "super secret",
    resave: false,
    saveUninitialized: true
}));
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
// Routes

app.get('/', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    const { name, email, password ,phone} = req.body;
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO clients (name, email, password,phone_number) VALUES ($1, $2, $3,$4)', [name, email, hashed,phone]);
    res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM clients WHERE email = $1', [email]);
    if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password)) {
        req.session.user = result.rows[0];
        res.render('choose-action',{user:req.session.user});
    } else {
        res.send('Invalid login');
    }
});
app.get('/forgot-password', (req, res) => res.render('forgot-password'));

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = new Date(Date.now() + 3600000); // 1 hour

  const result = await pool.query('SELECT * FROM clients WHERE email = $1', [email]);
  if (result.rows.length === 0) {
    return res.send('Email not found');
  }

  await pool.query(
    'UPDATE clients SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
    [token, expiry, email]
  );

  const resetLink = `http://localhost:3000/reset-password/${token}`;

  await transporter.sendMail({
    to: email,
    from: process.env.EMAIL_USER,
    subject: 'Reset your password',
    html: `<p>You requested a password reset.</p>
           <p>Click <a href="${resetLink}">here</a> to reset your password. This link is valid for 1 hour.</p>`
  });

  res.send('A reset link has been sent to your email.');
});

app.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const result = await pool.query(
    'SELECT * FROM clients WHERE reset_token = $1 AND reset_token_expiry > NOW()', [token]
  );

  if (result.rows.length === 0) {
    return res.send('Reset link is invalid or has expired.');
  }

  res.render('reset-password', { token });
});

app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const result = await pool.query(
    'SELECT * FROM clients WHERE reset_token = $1 AND reset_token_expiry > NOW()', [token]
  );

  if (result.rows.length === 0) {
    return res.send('Invalid or expired token.');
  }

  const hashed = await bcrypt.hash(password, 10);

  await pool.query(
    'UPDATE clients SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = $2',
    [hashed, token]
  );
  res.render('reset-success');
});


app.get('/choose-action', (req, res) => res.render('choose-action.ejs'));
app.get('/dashboard', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const events = await pool.query('SELECT * FROM events WHERE user_id = $1', [req.session.user.id]);
    res.render('dashboard', { user: req.session.user, events: events.rows });
});
app.get('/explore',(req,res)=>res.render('events-list'));
app.get('/create-event', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('create-event', { user: req.session.user });
});
//app.get('/create-event',(req,res)=>res.render('create-event.ejs'));

app.post('/create-event', async (req, res) => {
    const { title, description, date, time, location } = req.body;
    await pool.query(
        'INSERT INTO events (title, description, date, time, location, user_id) VALUES ($1, $2, $3, $4, $5, $6)',
        [title, description, date, time, location, req.session.user.id]
    );
    res.redirect('/dashboard');
});
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('profile', { user: req.session.user });
});
app.get('/settings',(req,res)=>res.render('settings.ejs'));
app.listen(process.env.PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
