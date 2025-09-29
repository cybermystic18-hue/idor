const express = require('express');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(morgan('tiny'));
app.use(cors());
app.use(express.json());

// Serve static frontend (optional)
app.use('/', express.static(path.join(__dirname, 'web')));

const USERS_FILE = path.join(__dirname, 'data', 'users.json');

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to load users.json', e);
    return [];
  }
}

// Basic health
app.get('/healthz', (req, res) => res.send('ok'));

// Me endpoint: simulate a logged-in user (id 2)
app.get('/api/me', (req, res) => {
  res.json({ me: { id: 2, profile: `/api/profile/2` } });
});

// Vulnerable profile endpoint (IDOR)
app.get('/api/profile/:id', (req, res) => {
  const id = Number(req.params.id);
  if (Number.isNaN(id)) return res.status(400).json({ error: 'invalid id' });
  const users = loadUsers();
  const profile = users.find(u => u.id === id);
  if (!profile) return res.status(404).json({ error: 'not found' });

  // Remove internal-only fields for non-admins? Intentionally not done.
  return res.json(profile);
});

// A small "directory" view to make the site look real (no auth)
app.get('/api/users', (req, res) => {
  const users = loadUsers();
  // return limited info
  const list = users.map(u => ({ id: u.id, username: u.username }));
  res.json(list);
});

const server = app.listen(PORT, () => {
  console.log(`OpenProfiles listening on port ${PORT}`);
});

module.exports = server;
