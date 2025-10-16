// server.js
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 1234;
const DB_PATH = path.join(__dirname, 'users.db');

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Open DB
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) return console.error("DB open error:", err);
  console.log("🗄️  Connected to SQLite DB at", DB_PATH);
});

// GET / => basic welcome (or serve index.html from public)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// GET /register => docs (JSON)
app.get('/register', (req, res) => {
  res.json({
    api: "SQL Injection Lab API",
    description: "POST /vuln-login demonstrates vulnerable SQL concatenation. POST /login demonstrates safe parameterized queries.",
    endpoints: {
      "POST /vuln-login": { "body": { "username": "string", "password": "string" }, "notes": "VULNERABLE — for demo only" },
      "POST /login": { "body": { "username":"string", "password":"string" }, "notes": "SECURE — uses parameterized queries" }
    }
  });
});

/*
  VULNERABLE LOGIN (for demonstration)
  - Constructs SQL via string concatenation (dangerous)
  - We print the constructed SQL to the console so students can inspect it
*/
app.post('/vuln-login', (req, res) => {
  const { username, password } = req.body;
  username.trim();
  password.trim();
  // Build vulnerable SQL (string concatenation)
  const sql = "SELECT * FROM users WHERE username = ? AND password = ? ;";
  console.log("🔴 [VULN] Constructed SQL:", sql, "using", [username, password]);
  // Query for the user to get the stored password
  db.get("SELECT password FROM users WHERE username = ?", [username], (err, row) => {
    if (err || !row) {
      console.error("[VULN] SQL error or user not found:", err);
      return res.status(401).json({ success: false, message: "VULN login failed" });
    }
    const gotPassword = row.password;
    const unhashedPassword = bcrypt.compareSync(password, gotPassword);
    console.log(gotPassword);
    
    console.log("Unhashed password:", unhashedPassword);

    // Check password and simulate vulnerable login
    if (unhashedPassword === true) {
      // Simulate vulnerable SQL query (for demo)
      db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err || !row) {
          return res.status(401).json({ success: false, message: "VULN login failed" });
        }
        return res.json({ success: true, message: `VULN login success for user: ${row.username}`, user: row.id, username: row.username });
      });
    } else {
      return res.status(401).json({ success: false, message: "VULN login failed" });
    }
  });
  // Execute vulnerable SQL
  // db.all(sql, [username, unhashedPassword], (err, rows) => {
  //   if (err) {
  //     console.error("[VULN] SQL error:", err);
  //     return res.status(500).json({ error: "DB error (vuln)" });
  //   }
  //   if (rows.length > 0) {
  //     // Simulated successful login
  //     return res.json({ success: true, message: `VULN login success for user: ${rows[0].username}`, user: rows[0] });
  //   } else {
  //     return res.status(401).json({ success: false, message: "VULN login failed" });
  //   }
  // });
});


/*
  SECURE LOGIN — uses parameterized query (placeholders)
  Prevents SQL injection because input is bound, not concatenated.
*/
app.post(
  '/login',
  // Optional: simple validation to improve UX
  body('username').trim().isLength({ min: 1 }).escape(),
  body('password').trim().isLength({ min: 1 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { username, password } = req.body;

    // Parameterized query with placeholders
    const sql = "SELECT * FROM users WHERE username = ? AND password = ?;";
    console.log("🟢 [SECURE] Executing parameterized SQL:", sql, "with params:", [username, password]);

    db.get(sql, [username, password], (err, row) => {
      if (err) {
        console.error("[SECURE] SQL error:", err);
        return res.status(500).json({ error: "DB error (secure)" });
      }
      if (row) {
        return res.json({ success: true, message: `SECURE login success for user: ${row.username}`, user: row });
      } else {
        return res.status(401).json({ success: false, message: "SECURE login failed" });
      }
    });
  }
);

// Optional: list users (for teacher demo only, not for production)
app.get('/admin/list-users', (req, res) => {
  db.all("SELECT id, username FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ users: rows });
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server Error:", err.stack);
  res.status(500).json({ error: "Server error" });
});

// Start
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
