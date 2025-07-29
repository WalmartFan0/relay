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

// Add bio and created_at to users
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  bio TEXT DEFAULT '',
  avatar TEXT DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.run(`CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`);

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
        </form><hr>`;

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

// Profile page
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const userId = req.session.user.id;

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    db.all('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', [userId], (err2, posts) => {
      let html = `<h2>${user.username}'s Profile</h2>
        <form method="POST" action="/update-bio">
          Bio:<br><textarea name="bio">${user.bio}</textarea><br>
          Avatar URL:<br><input name="avatar" value="${user.avatar}"/><br>
          <button type="submit">Save Profile</button>
        </form>
        <form method="POST" action="/change-password">
          <h3>Change Password</h3>
          <input name="oldpass" placeholder="Old password" type="password" required /><br>
          <input name="newpass" placeholder="New password" type="password" required /><br>
          <button type="submit">Change Password</button>
        </form>
        <a href="/board">Back to Board</a>
        <hr>`;

      posts.forEach((p) => {
        html += `<p>${p.created_at}: ${p.content}</p><hr>`;
      });

      res.send(html);
    });
  });
});

app.post('/update-bio', (req, res) => {
  const { bio, avatar } = req.body;
  db.run('UPDATE users SET bio = ?, avatar = ? WHERE id = ?', [bio, avatar, req.session.user.id], (err) => {
    res.redirect('/profile');
  });
});

app.post('/change-password', async (req, res) => {
  const { oldpass, newpass } = req.body;
  const uid = req.session.user.id;

  db.get('SELECT password FROM users WHERE id = ?', [uid], async (err, row) => {
    if (await bcrypt.compare(oldpass, row.password)) {
      const hashed = await bcrypt.hash(newpass, 10);
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, uid], (err2) => {
        res.redirect('/profile');
      });
    } else {
      res.send('Wrong current password');
    }
  });
});

// View another user
app.get('/user/:username', (req, res) => {
  const username = req.params.username;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user) return res.send('User not found');
    db.all('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', [user.id], (err2, posts) => {
      let html = `<h2>${user.username}'s Public Profile</h2>`;
      if (user.avatar) html += `<img src="${user.avatar}" width="100"><br>`;
      html += `<p>${user.bio}</p><hr>`;

      posts.forEach((p) => {
        html += `<p>${p.created_at}: ${p.content}</p><hr>`;
      });

      res.send(html);
    });
  });
});

// Admin view of all users
app.get('/admin/accounts', (req, res) => {
  if (!req.session.user) return res.send('Not authorized');

  db.all('SELECT username, created_at FROM users ORDER BY created_at DESC', [], (err, rows) => {
    let html = `<h2>All Accounts</h2><a href="/board">Back</a><hr>`;
    rows.forEach((user) => {
      html += `<p>${user.username} - Joined: ${user.created_at}</p>`;
    });
    res.send(html);
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
