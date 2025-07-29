const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const db = new sqlite3.Database(path.join(dataDir, 'users.db'));

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
  is_admin INTEGER DEFAULT 0
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

// Helper to get site message
function getSiteMessage(callback) {
  db.get('SELECT value FROM settings WHERE key = "site_message"', [], (err, row) => {
    callback(row ? row.value : '');
  });
}

// Home route
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

// Message board with delete button
app.get('/board', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const currentUser = req.session.user;

  getSiteMessage((siteMessage) => {
    db.all(
      `SELECT posts.id, posts.content, posts.created_at, users.username, users.id AS uid 
       FROM posts 
       JOIN users ON posts.user_id = users.id 
       ORDER BY posts.created_at DESC`,
      [],
      (err, rows) => {
        let html = `<h2>Message Board</h2>
          <a href="/logout">Log Out</a> | <a href="/profile">My Profile</a>
          <form method="POST" action="/post">
            <textarea name="content" required></textarea><br>
            <button type="submit">Post</button>
          </form>`;
        if (siteMessage) html += `<div style="border:1px dashed red;padding:10px;margin:10px 0"><strong>Site Message:</strong> ${siteMessage}</div>`;
        html += `<hr>`;

        rows.forEach((row) => {
          html += `<p><strong><a href="/user/${row.username}">${row.username}</a></strong> (${row.created_at}):<br>${row.content}`;
          if (currentUser.id === row.uid) {
            html += ` <form method="POST" action="/delete-post" style="display:inline">
                        <input type="hidden" name="post_id" value="${row.id}" />
                        <button type="submit">Delete</button>
                      </form>`;
          }
          html += `</p><hr>`;
        });

        res.send(html);
      }
    );
  });
});

app.post('/post', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const userId = req.session.user.id;
  const content = req.body.content;

  db.run(`INSERT INTO posts (user_id, content) VALUES (?, ?)`, [userId, content], (err) => {
    if (err) return res.send("Error saving post.");
    res.redirect('/board');
  });
});

app.post('/delete-post', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const postId = req.body.post_id;

  db.run(`UPDATE posts SET content = '[ Deleted ]' WHERE id = ? AND user_id = ?`, [postId, req.session.user.id], (err) => {
    if (err) return res.send("Error deleting post.");
    res.redirect('/board');
  });
});

app.get('/admin/console', (req, res) => {
  if (!req.session.user || req.session.user.username !== 'chris') {
    return res.send('Access denied');
  }
  res.send(`<h2>Admin Console</h2>
    <form method="POST" action="/admin/console">
      <input name="command" placeholder="Enter command" style="width:100%" required><br>
      <button type="submit">Run</button>
    </form>
    <p><a href="/board">Back to Board</a></p>`);
});

app.post('/admin/console', (req, res) => {
  if (!req.session.user || req.session.user.username !== 'chris') {
    return res.send('Access denied');
  }

  const cmd = req.body.command.trim();

  if (cmd.startsWith('SetMsg ')) {
    const msg = cmd.substring(7).replace(/"/g, '');
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('site_message', ?)`, [msg], (err) => {
      if (err) return res.send('Error setting message');
      res.redirect('/admin/console');
    });
  } else if (cmd.startsWith('administrate ')) {
    const user = cmd.split(' ')[1];
    db.run(`UPDATE users SET is_admin = 1 WHERE username = ?`, [user], (err) => {
      if (err) return res.send('Error promoting user');
      res.redirect('/admin/console');
    });
  } else if (cmd.startsWith('unadministrate ')) {
    const user = cmd.split(' ')[1];
    db.run(`UPDATE users SET is_admin = 0 WHERE username = ?`, [user], (err) => {
      if (err) return res.send('Error demoting user');
      res.redirect('/admin/console');
    });
  } else {
    res.send('Unknown command');
  }
});

// (Keep the rest of your profile, post, and user routes unchanged)
// ... (same as before)

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
