const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./database.sqlite');

const PORT = process.env.PORT || 3000;

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT,
    port TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new SQLiteStore,
  secret: 'replace-with-a-very-secure-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 86400000 // 1 day
  }
}));

// Middleware to check if user is logged in
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// -------- Routes ----------

// Home - redirect logged-in users to dashboard
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// Registration Page
app.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Registration Handler
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send('Please enter a username and password. <a href="/register">Try again</a>');
  }

  // Hash password
  const hash = await bcrypt.hash(password, 12);

  // Insert user into DB
  db.run(`INSERT INTO users(username, password) VALUES (?, ?)`, [username, hash], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.send('Username already exists. <a href="/register">Choose another</a>');
      }
      return res.send('Error during registration. <a href="/register">Try again</a>');
    }
    req.session.userId = this.lastID;
    req.session.username = username;
    res.redirect('/dashboard');
  });
});

// Login Page
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login Handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('Please provide username and password. <a href="/login">Try again</a>');
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) return res.send('Error. <a href="/login">Try again</a>');
    if (!user) return res.send('Invalid username or password. <a href="/login">Try again</a>');
    
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send('Invalid username or password. <a href="/login">Try again</a>');
    
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });
});

// Dashboard Page (protected)
app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API endpoint to save server IP and port for user
app.post('/api/allocate', requireLogin, (req, res) => {
  const userId = req.session.userId;
  let { ip, port } = req.body;

  if(!ip || !port) {
    return res.json({ success: false, message: 'IP address and port are required.' });
  }

  // Basic validation for IP/hostname and port (more robust validation can be added)
  ip = ip.trim();
  port = port.trim();

  if (port.length > 5 || !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
    return res.json({ success: false, message: 'Port must be a number between 1 and 65535' });
  }

  // Remove any existing server allocation for this user (for simplicity only one server entry per user)
  db.run(`DELETE FROM servers WHERE user_id = ?`, [userId], err => {
    if (err) {
      return res.json({ success: false, message: 'Database error.' });
    }
    // Insert new allocation
    db.run(`INSERT INTO servers(user_id, ip, port) VALUES (?, ?, ?)`, [userId, ip, port], err2 => {
      if (err2) {
        return res.json({ success: false, message: 'Database error inserting server.' });
      }
      res.json({ success: true, ip, port });
    });
  });
});

// API endpoint to get allocated server IP/port for user
app.get('/api/server', requireLogin, (req, res) => {
  db.get(`SELECT ip, port FROM servers WHERE user_id = ?`, [req.session.userId], (err, row) => {
    if (err) return res.json({ success: false, message: 'Database error.' });
    if (!row) return res.json({ success: false, message: 'No server allocated yet.' });
    res.json({ success: true, ip: row.ip, port: row.port });
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
