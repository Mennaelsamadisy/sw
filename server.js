const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const pool = require('./db/db');
require('dotenv').config();

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
app.get('/choose-action', (req, res) => res.render('choose-action.ejs'));
app.get('/dashboard', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const events = await pool.query('SELECT * FROM events WHERE user_id = $1', [req.session.user.id]);
    res.render('dashboard', { user: req.session.user, events: events.rows });
});

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

app.listen(process.env.PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
