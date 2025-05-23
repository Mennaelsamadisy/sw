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
app.use(bodyParser.json()); // (optional: for JSON body support)
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


app.get('/choose-action', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('choose-action', { user: req.session.user });
});


app.get('/explore',async(req,res)=>{
    try {
    const result = await pool.query(`
      SELECT 
        events.id, 
        events.title, 
        events.category, 
        events.event_date, 
        events.start_time, 
        events.location, 
        events.description,
        clients.name AS organizer_name
      FROM events
      JOIN clients ON events.client_id = clients.id
      ORDER BY event_date ASC
    `);

    res.render('events-list', { events: result.rows });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).send('Server error while loading events.');
  }
});

//app.get('/event/:id', async (req, res) => {
  //const { id } = req.params;
  //const result = await pool.query('SELECT * FROM events WHERE id = $1', [id]);

  //if (result.rows.length === 0) {
    //return res.send('Event not found');
  //}

  //res.render('event-details', { event: result.rows[0] });
//});

app.get('/create-event', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('create-event', { user: req.session.user });
});

/* app.post('/create-event', async (req, res) => {
    const { title, description, date, time, location } = req.body;
    await pool.query(
        'INSERT INTO events (title, description, date, time, location, user_id) VALUES ($1, $2, $3, $4, $5, $6)',
        [title, description, date, time, location, req.session.user.id]
    );
    res.redirect('/dashboard');
}); */
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('profile', { user: req.session.user });
});

app.post('/update-profile', async (req, res) => {
  const { name } = req.body;
  const userId = req.session.user.id;

  await pool.query(
    `UPDATE clients SET name = $1 WHERE id = $2`,
    [name, userId]
  );

  // Update session
  req.session.user.name = name;

  res.redirect('/profile');
});

app.get('/change-password', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('change-password');
});

app.post('/change-password', async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;
  const userId = req.session.user.id;

  const result = await pool.query('SELECT * FROM clients WHERE id = $1', [userId]);
  const user = result.rows[0];

  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) return res.send('Incorrect current password');

  if (newPassword !== confirmPassword) return res.send('Passwords do not match');

  const hashed = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE clients SET password = $1 WHERE id = $2', [hashed, userId]);

  res.send('Password changed successfully. <a href="/profile">Go back to profile</a>');
});

app.get('/delete-account', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('delete-account');
});

app.post('/delete-account', async (req, res) => {
  const userId = req.session.user.id;

  await pool.query('DELETE FROM clients WHERE id = $1', [userId]);
  req.session.destroy(); // logout the user
  res.send('Your account has been deleted. <a href="/register">Register Again</a>');
});


//app.get('/settings',(req,res)=>res.render('settings.ejs'));
app.listen(process.env.PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

const { v4: uuidv4 } = require('uuid');

app.post('/create-event', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login'); // or res.status(401).send('Unauthorized')
  }
  try {
    const {
      eventName,
      category,
      eventDate,
      startTime,
      location,
      description
    } = req.body;

    const clientId = req.session.user.id;

    // Insert event without specifying UUID
    const result = await pool.query(`
      INSERT INTO events (title, category, event_date, start_time, location, description, client_id, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING id
    `, [
      eventName,
      category,
      eventDate,
      startTime,
      location,
      description,
      clientId
    ]);

    const eventId = result.rows[0].id;

    // Parse ticket categories
    const ticketCategories = [];
    let i = 0;
    while (req.body[`ticketName${i}`]) {
      ticketCategories.push({
        category_id: uuidv4(),
        name: req.body[`ticketName${i}`],
        price: parseFloat(req.body[`ticketPrice${i}`]),
        total: parseInt(req.body[`ticketPlaces${i}`]),
        remaining: parseInt(req.body[`ticketPlaces${i}`])
      });
      i++;
    }

    // Insert each ticket category with the retrieved event ID
    for (const ticket of ticketCategories) {
      await pool.query(`
        INSERT INTO ticketcategories (event_id, category_id, category_name, category_price, total_tickets, remaining_tickets)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [
        eventId,
        ticket.category_id,
        ticket.name,
        ticket.price,
        ticket.total,
        ticket.remaining
      ]);
    }

    res.redirect('/choose-action');
  } catch (err) {
    console.error('Error creating event and tickets:', err);
    res.status(500).send('Internal Server Error');
  }
});
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Error while logging out');
    }

    res.clearCookie('connect.sid'); // clears the session cookie
    res.redirect('/login'); // redirect to login or homepage
  });
});
app.get('/event/:id', async (req, res) => {
  const eventId = req.params.id;

  const eventResult = await pool.query(`
    SELECT e.*, c.name AS organizer
    FROM events e
    JOIN clients c ON e.client_id = c.id
    WHERE e.id = $1
  `, [eventId]);

  const ticketResult = await pool.query(`
    SELECT * FROM ticketcategories WHERE event_id = $1
  `, [eventId]);

  if (eventResult.rows.length === 0) {
    return res.send('Event not found.');
  }

  res.render('book-ticket', {
    event: eventResult.rows[0],
    tickets: ticketResult.rows
  });
});

//app.use((req, res, next) => {
  //if (!req.session.user) {
    //req.session.user = { id: '2aca1f95-4fdb-47ff-9840-a59382e77a5e' }; // real UUID from DB
  //}
  //next();
//});

