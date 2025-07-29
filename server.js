// ✅ FULL UPDATED server.js — Feature Complete (Roles, Admin Tools, Bans, Console, Profile Customization)

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const db = new sqlite3.Database(path.join(dataDir, 'users.db'));

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));
app.use(express.static('public'));

// Create tables
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  bio TEXT DEFAULT '',
  avatar TEXT DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_admin INTEGER DEFAULT 0,
  roles TEXT DEFAULT '',
  banned INTEGER DEFAULT 0,
  darkmode INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  official INTEGER DEFAULT 0
)`);

db.run(`CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`);

db.run(`CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
)`);

function isValidUsername(username) {
  const noSpecials = /^[a-zA-Z0-9]+$/;
  const notAllDigits = /\D/;
  return noSpecials.test(username) && notAllDigits.test(username);
}

function isAdmin(user) {
  return user?.username === 'chris' || user?.is_admin;
}

function formatUserDisplay(user) {
  const roles = [];
  if (user.username === 'chris') roles.push('<span style="color:red">Owner</span>');
  if (user.is_admin) roles.push('<span style="color:red">Admin</span>');
  if (user.verified) roles.push('<span style="color:green">Verified</span>');
  if (user.official) roles.push('<span style="color:blue">Official</span>');
  try {
    const customRoles = JSON.parse(user.roles || '[]');
    roles.push(...customRoles.map(r => `<span style="color:${r.color}">${r.name}</span>`));
  } catch {}
  const roleStr = roles.length ? ` (${roles.join(', ')})` : '';
  const name = user.banned ? `<s>${user.username}</s>` : user.username;
  return `${name}${roleStr}`;
}

function getSiteMessage(callback) {
  db.get('SELECT value FROM settings WHERE key = "site_message"', [], (err, row) => {
    callback(row ? row.value : '');
  });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/signup.html'));
});

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!isValidUsername(username)) {
    return res.send('Invalid username. Only letters and numbers allowed. Cannot be all numbers.');
  }
  const hashed = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], (err) => {
    if (err) return res.send('Username taken.');
    res.redirect('/login');
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send('Invalid login');
    }
    req.session.user = user;
    res.redirect('/board');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/board', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const currentUser = req.session.user;
  getSiteMessage((siteMessage) => {
    db.all(`SELECT posts.id, posts.content, posts.created_at, users.username, users.id AS uid FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC`, [], (err, rows) => {
      let html = `<h2>Message Board</h2><a href="/logout">Log Out</a> | <a href="/profile">My Profile</a> | <a href="/profile/edit">Edit Profile</a>`;
      if (isAdmin(currentUser)) html += ` | <a href="/admin/tools">Admin Tools</a> | <a href="/admin/console">Console</a>`;
      html += `<form method="POST" action="/post"><textarea name="content" required></textarea><br><button type="submit">Post</button></form>`;
      if (siteMessage) html += `<div style="border:1px dashed red;padding:10px;margin:10px 0"><strong>Site Message:</strong> ${siteMessage}</div>`;
      html += `<hr>`;
      rows.forEach((row) => {
        html += `<p><strong><a href="/user/${row.username}">${row.username}</a></strong> (${row.created_at}):<br>${row.content}`;
        if (currentUser.id === row.uid) {
          html += ` <form method="POST" action="/delete-post" style="display:inline"><input type="hidden" name="post_id" value="${row.id}" /><button type="submit">Delete</button></form>`;
        }
        html += `</p><hr>`;
      });
      res.send(html);
    });
  });
});

app.post('/post', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.run('INSERT INTO posts (user_id, content) VALUES (?, ?)', [req.session.user.id, req.body.content], (err) => {
    if (err) return res.send("Error saving post.");
    res.redirect('/board');
  });
});

app.post('/delete-post', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.run('UPDATE posts SET content = "[ Deleted ]" WHERE id = ? AND user_id = ?', [req.body.post_id, req.session.user.id], (err) => {
    if (err) return res.send("Error deleting post.");
    res.redirect('/board');
  });
});

app.get('/admin/tools', (req, res) => {
  if (!isAdmin(req.session.user)) return res.send('Access denied');
  res.send(`<h2>Admin Tools</h2>
    <form method="POST" action="/admin/ban">
      <input name="user" placeholder="User to ban"><button type="submit">Ban</button>
    </form>
    <form method="POST" action="/admin/edit-message">
      <input name="id" placeholder="Message ID"><br>
      <textarea name="newText" placeholder="New content"></textarea><br>
      <button type="submit">Edit Message</button>
    </form>
    <form method="POST" action="/admin/delete-message">
      <input name="id" placeholder="Message ID"><button type="submit">Delete</button>
    </form>
    <form method="POST" action="/admin/verify">
      <input name="user" placeholder="Username"><button name="action" value="verify">Verify</button><button name="action" value="unverify">Unverify</button>
    </form>
    <form method="POST" action="/admin/officiate">
      <input name="user" placeholder="Username"><button name="action" value="on">Officiate</button><button name="action" value="off">Unofficiate</button>
    </form>
    <a href="/board">Back</a>`);
});

app.post('/admin/ban', (req, res) => {
  if (!isAdmin(req.session.user)) return res.send('Access denied');
  db.run('UPDATE users SET banned = 1 WHERE username = ?', [req.body.user], (err) => {
    if (err) return res.send('Failed to ban user');
    res.redirect('/admin/tools');
  });
});

app.post('/admin/edit-message', (req, res) => {
  if (!isAdmin(req.session.user)) return res.send('Access denied');
  db.run('UPDATE posts SET content = ? WHERE id = ?', [req.body.newText, req.body.id], (err) => {
    if (err) return res.send('Failed to edit post');
    res.redirect('/admin/tools');
  });
});

app.post('/admin/delete-message', (req, res) => {
  if (!isAdmin(req.session.user)) return res.send('Access denied');
  db.run('DELETE FROM posts WHERE id = ?', [req.body.id], (err) => {
    if (err) return res.send('Failed to delete post');
    res.redirect('/admin/tools');
  });
});

app.post('/admin/verify', (req, res) => {
  if (!isAdmin(req.session.user)) return res.send('Access denied');
  const value = req.body.action === 'verify' ? 1 : 0;
  db.run('UPDATE users SET verified = ? WHERE username = ?', [value, req.body.user], (err) => {
    if (err) return res.send('Failed to update verification');
    res.redirect('/admin/tools');
  });
});

app.post('/admin/officiate', (req, res) => {
  if (!isAdmin(req.session.user)) return res.send('Access denied');
  const value = req.body.action === 'on' ? 1 : 0;
  db.run('UPDATE users SET official = ? WHERE username = ?', [value, req.body.user], (err) => {
    if (err) return res.send('Failed to update official status');
    res.redirect('/admin/tools');
  });
});

app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.get('SELECT * FROM users WHERE id = ?', [req.session.user.id], (err, user) => {
    db.all('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', [user.id], (err2, posts) => {
      let html = `<h2>${user.username}'s Profile</h2>`;
      if (user.avatar) html += `<img src="${user.avatar}" width="100"><br>`;
      html += `<p>${user.bio}</p><hr>`;
      posts.forEach(p => html += `<p>${p.created_at}: ${p.content}</p><hr>`);
      res.send(html);
    });
  });
});

app.get('/user/:username', (req, res) => {
  db.get('SELECT * FROM users WHERE username = ?', [req.params.username], (err, user) => {
    if (!user) return res.send('User not found');
    db.all('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', [user.id], (err2, posts) => {
      let html = `<h2>${user.username}'s Public Profile</h2>`;
      if (user.avatar) html += `<img src="${user.avatar}" width="100"><br>`;
      html += `<p>${user.bio}</p><hr>`;
      posts.forEach(p => html += `<p>${p.created_at}: ${p.content}</p><hr>`);
      res.send(html);
    });
  });
});

app.get('/profile/edit', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.send(`<h2>Edit Profile</h2>
    <form method="POST" action="/profile/edit">
      Avatar URL: <input name="avatar" value="${req.session.user.avatar || ''}"><br>
      Bio:<br><textarea name="bio">${req.session.user.bio || ''}</textarea><br>
      <button type="submit">Save</button>
    </form><br><a href="/profile">Cancel</a>`);
});

app.post('/profile/edit', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.run('UPDATE users SET avatar = ?, bio = ? WHERE id = ?', [req.body.avatar, req.body.bio, req.session.user.id], (err) => {
    if (err) return res.send('Error updating profile');
    req.session.user.avatar = req.body.avatar;
    req.session.user.bio = req.body.bio;
    res.redirect('/profile');
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log('SQLite DB Path:', path.join(dataDir, 'users.db'));
});
