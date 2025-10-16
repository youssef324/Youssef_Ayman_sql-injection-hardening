// init-db.js
const sqlite3 = require('sqlite3').verbose();
const dbFile = './users.db';
const db = new sqlite3.Database(dbFile);
const bcrypt = require('bcrypt');
const saltRounds = 10;

db.serialize(() => {
  // Drop table if exists — for clean re-run
  db.run("DROP TABLE IF EXISTS users");

  // Create users table
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    );
  `);

  // NOTE: For educational clarity we store plaintext passwords here.
  // In real apps ALWAYS store hashed passwords (bcrypt/argon2).
  const stmt = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
  const textPassword = "admin123";
  const password = bcrypt.hashSync(textPassword, saltRounds);
  stmt.run("admin", password);
  stmt.finalize();

  console.log("✅ Database initialized with sample users (users.db).");

  console.log(password);
  
});

db.close();
