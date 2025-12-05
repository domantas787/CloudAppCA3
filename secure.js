
// secure version of the blog app

const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const csurf = require('csurf');
const morgan = require('morgan');

const app = express();
const dbPath = path.join(__dirname, 'db', 'secure-blog.sqlite');
const db = new sqlite3.Database(dbPath);

// database(secure: hashed passwords, logs table)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password_hash TEXT,
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

  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT,
      ip TEXT,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// app config
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views_secure'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(morgan('combined'));

app.use(
  session({
    secret: 'env-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax'
      // HTTPS
    }
  })
);

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'", "'unsafe-inline'"]
      }
    }
  })
);

// CSRF protection
app.use(csurf());

// tokens
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  res.locals.user = req.session.user || null;
  next();
});

// simple logger
function logAction(userId, action, ip, details) {
  db.run(
    'INSERT INTO logs (user_id, action, ip, details) VALUES (?, ?, ?, ?)',
    [userId || null, action, ip, details || ''],
    (err) => {
      if (err) console.error('Log insert error:', err);
    }
  );
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

app.get('/', (req, res) => {
  res.redirect('/posts');
});

// secure register
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.render('register', { error: 'All fields are required.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username.trim(), email.trim(), passwordHash],
      function (err) {
        if (err) {
          console.error('Register error:', err);
          return res.render('register', {
            error: 'Could not register user.'
          });
        }
        logAction(this.lastID, 'register', req.ip, 'New user registered');
        res.redirect('/login');
      }
    );
  } catch (err) {
    next(err);
  }
});

// secure login/logout
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('login', { error: 'Username and password required.' });
  }

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username.trim()],
    async (err, user) => {
      if (err) {
        console.error('Login error:', err);
        return next(err);
      }
      if (!user) {
        logAction(null, 'login_failed', req.ip, 'Unknown username');
        return res.render('login', { error: 'Invalid credentials.' });
      }

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        logAction(user.id, 'login_failed', req.ip, 'Wrong password');
        return res.render('login', { error: 'Invalid credentials.' });
      }

      req.session.user = { id: user.id, username: user.username, role: user.role };
      logAction(user.id, 'login_success', req.ip, 'User logged in');
      res.redirect('/posts');
    }
  );
});

app.post('/logout', (req, res) => {
  if (req.session.user) {
    logAction(req.session.user.id, 'logout', req.ip, 'User logged out');
  }
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// secure search and list posts
app.get('/posts', (req, res, next) => {
  const q = (req.query.q || '').trim();

  let sql =
    'SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id';
  const params = [];

  if (q) {
    sql += ' WHERE title LIKE ? OR content LIKE ?';
    params.push('%' + q + '%', '%' + q + '%');
  }

  sql += ' ORDER BY created_at DESC';

  db.all(sql, params, (err, posts) => {
    if (err) return next(err);
    res.render('posts', { posts, q });
  });
});

// new post
app.get('/posts/new', requireLogin, (req, res) => {
  res.render('new-post', { error: null });
});

app.post('/posts', requireLogin, (req, res, next) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.render('new-post', { error: 'Title and content are required.' });
  }

  db.run(
    'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)',
    [req.session.user.id, title.trim(), content.trim()],
    function (err) {
      if (err) return next(err);
      logAction(req.session.user.id, 'create_post', req.ip, 'Post ' + this.lastID);
      res.redirect('/posts/' + this.lastID);
    }
  );
});

// view posts and comments
app.get('/posts/:id', (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) return res.status(400).send('Invalid ID');

  db.get(
    'SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = ?',
    [id],
    (err, post) => {
      if (err) return next(err);
      if (!post) return res.status(404).send('Post not found');

      db.all(
        'SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ? ORDER BY created_at ASC',
        [id],
        (err, comments) => {
          if (err) return next(err);
          res.render('post', { post, comments, error: null });
        }
      );
    }
  );
});

// secure add comments
app.post('/posts/:id/comments', requireLogin, (req, res, next) => {
  const postId = parseInt(req.params.id, 10);
  const { content } = req.body;

  if (!content) {
    return res.redirect('/posts/' + postId);
  }

  db.run(
    'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
    [postId, req.session.user.id, content.trim()],
    function (err) {
      if (err) return next(err);
      logAction(
        req.session.user.id,
        'add_comment',
        req.ip,
        'Comment ' + this.lastID + ' on post ' + postId
      );
      res.redirect('/posts/' + postId);
    }
  );
});



// error handler 
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('An internal error occurred.');
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log('Secure app listening on http://localhost:' + PORT);
});
