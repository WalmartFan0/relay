const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const fs = require('fs');
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
    password TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// Routes
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

// Show the message board
app.get('/board', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    db.all(
        `SELECT posts.content, posts.created_at, users.username 
         FROM posts 
         JOIN users ON posts.user_id = users.id 
         ORDER BY posts.created_at DESC`,
        [],
        (err, rows) => {
            let html = `<h2>Message Board</h2>
            <form method="POST" action="/post">
              <textarea name="content" required></textarea><br>
              <button type="submit">Post</button>
            </form>
            <hr>`;
            rows.forEach((row) => {
                html += `<p><strong>${row.username}</strong> (${row.created_at}):<br>${row.content}</p><hr>`;
            });
            res.send(html);
        }
    );
});

// Handle posting a new message
app.post('/post', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    const userId = req.session.user.id;
    const content = req.body.content;

    db.run(
        `INSERT INTO posts (user_id, content) VALUES (?, ?)`,
        [userId, content],
        (err) => {
            if (err) return res.send("Error saving post.");
            res.redirect('/board');
        }
    );
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});
