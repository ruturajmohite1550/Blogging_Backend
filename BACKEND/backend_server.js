require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
}));
app.use(express.json());

// In-memory login attempts tracker: { email: { count: number, lastAttempt: timestamp } }
const loginAttempts = {};

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Token missing' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// User Signup (with reCAPTCHA)
app.post('/api/signup', async (req, res) => {
  const { username, email, password, token } = req.body;

  if (!token) {
    return res.status(400).json({ message: 'CAPTCHA token missing' });
  }

  try {
    const verifyResponse = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`
    );

    if (!verifyResponse.data.success) {
      return res.status(400).json({ message: 'CAPTCHA verification failed' });
    }

    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [insertResult] = await pool.query(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );

    const userId = insertResult.insertId;
    const jwtToken = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ token: jwtToken, userId, username });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// User Login (with CAPTCHA after 3 failed attempts)
app.post('/api/login', async (req, res) => {
  const { email, password, token } = req.body;

  // Initialize or get attempt count for this email
  if (!loginAttempts[email]) {
    loginAttempts[email] = { count: 0, lastAttempt: Date.now() };
  }

  // Reset count after cooldown period (15 minutes)
  const cooldown = 15 * 60 * 1000;
  if (Date.now() - loginAttempts[email].lastAttempt > cooldown) {
    loginAttempts[email] = { count: 0, lastAttempt: Date.now() };
  }

  // If attempts >= 3, require captcha token
  if (loginAttempts[email].count >= 3) {
    if (!token) {
      return res.status(400).json({ 
        message: 'CAPTCHA required after multiple failed attempts', 
        showCaptcha: true 
      });
    }

    // Verify CAPTCHA token with Google
    try {
      const verifyResponse = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`
      );
      if (!verifyResponse.data.success) {
        return res.status(400).json({ 
          message: 'CAPTCHA verification failed', 
          showCaptcha: true 
        });
      }
    } catch (err) {
      return res.status(500).json({ 
        message: 'CAPTCHA verification error', 
        showCaptcha: true 
      });
    }
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      loginAttempts[email].count++;
      loginAttempts[email].lastAttempt = Date.now();
      return res.status(400).json({ 
        message: 'Invalid credentials', 
        showCaptcha: loginAttempts[email].count >= 3 
      });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      loginAttempts[email].count++;
      loginAttempts[email].lastAttempt = Date.now();
      return res.status(400).json({ 
        message: 'Invalid credentials', 
        showCaptcha: loginAttempts[email].count >= 3 
      });
    }

    // Successful login — reset attempts
    loginAttempts[email] = { count: 0, lastAttempt: Date.now() };

    const jwtToken = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token: jwtToken, username: user.username, userId: user.id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Create blog post
app.post('/api/posts', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.id;
  try {
    await pool.query('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)', [title, content, userId]);
    res.status(201).json({ message: 'Post created' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get all posts (public)
app.get('/api/posts', async (req, res) => {
  try {
    const [posts] = await pool.query(`
      SELECT p.id, p.title, LEFT(p.content, 150) AS summary, p.created_at, u.username AS author
      FROM posts p
      JOIN users u ON p.author_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get single post by id (public)
app.get('/api/posts/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const [posts] = await pool.query(`
      SELECT p.id, p.title, p.content, p.created_at, u.username AS author
      FROM posts p
      JOIN users u ON p.author_id = u.id
      WHERE p.id = ?
    `, [id]);

    if (posts.length === 0) return res.status(404).json({ message: 'Post not found' });
    res.json(posts[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get posts by logged-in user
app.get('/api/my-posts', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const [posts] = await pool.query('SELECT id, title, content, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC', [userId]);
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Edit post (only author)
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const { title, content } = req.body;
  const userId = req.user.id;
  try {
    const [posts] = await pool.query('SELECT author_id FROM posts WHERE id = ?', [id]);
    if (posts.length === 0) return res.status(404).json({ message: 'Post not found' });
    if (posts[0].author_id !== userId) return res.status(403).json({ message: 'Not authorized' });

    await pool.query('UPDATE posts SET title = ?, content = ? WHERE id = ?', [title, content, id]);
    res.json({ message: 'Post updated' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Delete post (only author)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;
  try {
    const [posts] = await pool.query('SELECT author_id FROM posts WHERE id = ?', [id]);
    if (posts.length === 0) return res.status(404).json({ message: 'Post not found' });
    if (posts[0].author_id !== userId) return res.status(403).json({ message: 'Not authorized' });

    await pool.query('DELETE FROM posts WHERE id = ?', [id]);
    res.json({ message: 'Post deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(PORT,() => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
