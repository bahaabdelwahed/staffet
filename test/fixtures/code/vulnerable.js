// Test fixture: deliberately vulnerable code.
const { exec } = require('child_process');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function handler(req, res, db, el) {
  exec(`ls ${req.query.dir}`);
  db.query("SELECT * FROM u WHERE id = " + req.query.id);
  db.query(`SELECT * FROM u WHERE id = ${req.query.id}`);
  db.query("SELECT * FROM u WHERE id = ?", [req.query.id]); // safe: placeholder
  el.innerHTML = req.query.html;
  el.innerHTML = "<b>ok</b>"; // safe: constant
  eval(req.body.code);
  const token = Math.random().toString(36);
  crypto.createHash("md5");
  res.redirect(req.query.next);
  res.send(`<h1>${req.query.name}</h1>`);
  fs.readFile(req.query.file, cb);
  const agent = new https.Agent({ rejectUnauthorized: false });
  jwt.sign({ a: 1 }, "supersecret");
  try { x(); } catch (e) { }
  if (a === a) { y(); }
  if (b = 3) { y(); }
}
