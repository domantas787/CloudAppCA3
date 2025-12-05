const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');

const app = express();
const dbPath = path.join(__dirname, 'db', 'insecure-blog.sqlite');

//DB SETUP (insecure: plaintext passwords, no constraints)
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password TEXT,
      role TEXT DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER,
      user_id INTEGER,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

//APP CONFIG (NO security middleware here)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views_insecure'));

app.use(bodyParser.urlencoded({ extended: false }));

// intentionally weak session config
app.use(
  session({
    secret: 'insecure-secret', // hard-coded, guessable
    resave: false,
    saveUninitialized: true
    // no cookie flags
  })
);

// insecure logs (log entire body including passwords)
app.use((req, res, next) => {
  console.log('INSECURE LOG - body:', req.body);
  next();
});

// make user available in views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// auth check
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// routes

app.get('/', (req, res) => {
  res.redirect('/posts');
});

// registration (plaintext password, no validation)
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  // sql plaintext password
  const sql =
    "INSERT INTO users (username, email, password) VALUES ('" +
    username +
    "', '" +
    email +
    "', '" +
    password +
    "')";
  db.run(sql, function (err) {
    if (err) {
      console.error('Register error:', err);
      return res.render('register', { error: 'Could not register user.' });
    }
    res.redirect('/login');
  });
});

// login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // vulnerable to SQL injection
  const sql =
    "SELECT * FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  db.get(sql, (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.render('login', { error: 'Error logging in.' });
    }
    if (!user) {
      return res.render('login', { error: 'Invalid credentials.' });
    }
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect('/posts');
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// list posts
app.get('/posts', (req, res) => {
  const q = req.query.q || '';

  let sql =
    'SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id';
  if (q) {
    // search vulnerable to SQL injection
    sql += " WHERE title LIKE '%" + q + "%' OR content LIKE '%" + q + "%'";
  }
  sql += ' ORDER BY created_at DESC';

  db.all(sql, (err, posts) => {
    if (err) {
      console.error('Error loading posts:', err);
      return res.status(500).send(err.stack); // stack trace
    }
    res.render('posts', { posts, q });
  });
});

// new post (logged in)
app.get('/posts/new', requireLogin, (req, res) => {
  res.render('new-post', { error: null });
});

app.post('/posts', requireLogin, (req, res) => {
  const { title, content } = req.body;
  // no validation
  const sql =
    "INSERT INTO posts (user_id, title, content) VALUES (" +
    req.session.user.id +
    ", '" +
    title +
    "', '" +
    content +
    "')";
  db.run(sql, function (err) {
    if (err) {
      console.error('Error creating post:', err);
      return res.render('new-post', { error: 'Could not create post.' });
    }
    res.redirect('/posts/' + this.lastID);
  });
});

// view posts
app.get('/posts/:id', (req, res) => {
  const id = req.params.id;

  const postSql =
    'SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = ' +
    id;
  const commentSql =
    'SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ' +
    id +
    ' ORDER BY created_at ASC';

  db.get(postSql, (err, post) => {
    if (err) {
      console.error('Error loading post:', err);
      return res.status(500).send(err.stack);
    }
    if (!post) return res.status(404).send('Post not found');

    db.all(commentSql, (err, comments) => {
      if (err) {
        console.error('Error loading comments:', err);
        return res.status(500).send(err.stack);
      }
      res.render('post', { post, comments, error: null });
    });
  });
});

// add comment (stored XSS)
app.post('/posts/:id/comments', requireLogin, (req, res) => {
  const postId = req.params.id;
  const { content } = req.body;

  const sql =
    "INSERT INTO comments (post_id, user_id, content) VALUES (" +
    postId +
    ', ' +
    req.session.user.id +
    ", '" +
    content +
    "')";
  db.run(sql, function (err) {
    if (err) {
      console.error('Error adding comment:', err);
      return res.redirect('/posts/' + postId);
    }
    res.redirect('/posts/' + postId);
  });
});

// error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send(err.stack);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log('Insecure app listening on http://localhost:' + PORT);
});
