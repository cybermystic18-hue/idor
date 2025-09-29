/**
 * server.js
 * Realistic Express app for IDOR CTF.
 *
 * Token format used by the site:
 *   token = base64url(JSON payload) + "." + HMAC_SHA256_HEX(payload, SECRET)
 *
 * The server signs tokens with SECRET and validates them on /api/profile.
 *
 * Vulnerability (intentional): the secret is accidentally included client-side
 * in `web/config.js`. Players must inspect public assets and craft a token
 * with "id": 1 (admin) to retrieve the flag.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const morgan = require('morgan');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// NOTE: In a real app this would be in an env var and NEVER exposed client-side.
// For this CTF the SECRET is intentionally constant and also included in web/config.js
// to simulate a realistic accidental leak that players must find.
const SECRET = process.env.CHALLENGE_SECRET || 'c0mpl3x_but_leaked_secret_2025!';

// helpers
function b64u(input) {
  return Buffer.from(input).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function b64uDecode(input) {
  // pad
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}
function hmacHex(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// file-backed "database"
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (e) {
    console.error('failed to load users.json', e);
    return [];
  }
}
function findById(id) {
  return loadUsers().find(u => Number(u.id) === Number(id));
}

// middleware
app.use(morgan('tiny'));
app.use(cors());
app.use(express.json());

// serve static frontend and assets
app.use('/', express.static(path.join(__dirname, 'web')));

// health
app.get('/healthz', (req, res) => res.send('ok'));

/**
 * Public directory listing (no ids) — names only so IDs are hidden.
 * This simulates a front page that lists users by handle/username but doesn't expose
 * internal numeric IDs.
 */
app.get('/api/users', (req, res) => {
  const users = loadUsers();
  // return only public-visible fields (no id, no emails)
  const list = users.map(u => ({ username: u.username, bio: u.bio ? (u.bio.slice(0, 80)) : '' }));
  res.json({ count: list.length, users: list });
});

/**
 * /api/me - simulate a logged-in user (id=2). Returns a short-lived token and
 * a profile URL that includes that token. The token format is intentionally
 * simple and verifiable if someone knows the SECRET.
 */
app.get('/api/me', (req, res) => {
  const me = { id: 2, username: 'alice' };
  // include a small expiry (epoch seconds)
  const payload = { id: me.id, username: me.username, exp: Math.floor(Date.now() / 1000) + 60 * 60 }; // 1 hour
  const payloadStr = JSON.stringify(payload);
  const encoded = b64u(payloadStr);
  const mac = hmacHex(encoded, SECRET);
  const token = `${encoded}.${mac}`;
  // provide the token and a profile endpoint that accepts the token
  res.json({
    me,
    token,
    profile_url: `/api/profile?token=${encodeURIComponent(token)}`,
    note: 'This token is what the front-end uses to fetch your profile.'
  });
});

/**
 * Vulnerable profile endpoint — accepts a token, verifies HMAC and expiry,
 * then returns the profile for the token's id.
 *
 * Players should discover they can forge a token for id=1 (admin) if they
 * somehow learn the SECRET (accidentally included in public assets).
 */
app.get('/api/profile', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: 'token required' });

  const parts = token.split('.');
  if (parts.length !== 2) return res.status(400).json({ error: 'invalid token format' });
  const [encoded, mac] = parts;

  // verify mac
  const expected = hmacHex(encoded, SECRET);
  if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(mac, 'hex'))) {
    return res.status(403).json({ error: 'invalid token signature' });
  }

  let payloadStr;
  try {
    payloadStr = b64uDecode(encoded);
  } catch (e) {
    return res.status(400).json({ error: 'invalid token payload' });
  }

  let payload;
  try {
    payload = JSON.parse(payloadStr);
  } catch (e) {
    return res.status(400).json({ error: 'malformed payload' });
  }

  // check expiry
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
    return res.status(403).json({ error: 'token expired' });
  }

  const user = findById(payload.id);
  if (!user) return res.status(404).json({ error: 'profile not found' });

  // realistic: hide internal fields for non-admins; but admin record contains flag.
  // For realism, we'll hide email for any user unless token id matches requested id.
  const publicProfile = {
    id: user.id,
    username: user.username,
    bio: user.bio
  };

  // If the token owner is the same as the profile, include email.
  if (Number(payload.id) === Number(user.id)) {
    publicProfile.email = user.email;
  }

  // If the requested profile is admin (id=1) and the token belongs to admin, include the flag.
  // Otherwise do not include the flag.
  if (user.id === 1) {
    if (Number(payload.id) === 1) {
      publicProfile.flag = user.flag; // admin sees own flag
    } else {
      // do not leak flag to other users
      // but include a soft message so players know something is special about admin's profile
      publicProfile.note = 'This profile is restricted.';
    }
  }

  return res.json(publicProfile);
});

/**
 * small helper for debug in CTF local runs (not linked from UI)
 */
app.get('/__internal/list-raw', (req, res) => {
  // DO NOT link this route in the real challenge; leave it for admins only.
  // For the CTF deployment we keep it disabled by default unless DEBUG env is set.
  if (!process.env.DEBUG) return res.status(404).send('not found');
  res.json(loadUsers());
});

app.listen(PORT, () => {
  console.log(`OpenProfiles listening on port ${PORT}`);
  console.log(`(Using SECRET: ${SECRET.slice(0, 8)}... for debugging)`);
});
