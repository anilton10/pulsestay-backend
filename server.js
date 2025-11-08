// server.js — Demo backend for PulseStay (SQLite for demo). NOT production.
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const cors = require('cors');
const SECRET = 'dev_secret_replace_in_production';

if (!fs.existsSync('./data.db')) {
  const db = new sqlite3.Database('./data.db');
  db.serialize(() => {
    db.run(`CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, disabled INTEGER DEFAULT 0)`);
    db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, password TEXT, role TEXT, tenant_id INTEGER, disabled INTEGER DEFAULT 0)`);
    db.run(`CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, number TEXT, category TEXT, status TEXT, notes TEXT)`);
    db.run(`CREATE TABLE history (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, action TEXT, actor TEXT, timestamp TEXT, details TEXT)`);
    const pass = bcrypt.hashSync('Pulse@123', 10);
    db.run(`INSERT INTO users (email,password,role,tenant_id) VALUES (?,?,?,?)`, ['pulse@pulse.stay', pass, 'super_admin', NULL]);
  });
  db.close();
}

const db = new sqlite3.Database('./data.db');
const app = express();
app.use(bodyParser.json());
app.use(cors());
function now(){ return new Date().toISOString(); }

function authMiddleware(req,res,next){
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send({error:'no token'});
  const token = auth.split(' ')[1];
  try{
    const payload = jwt.verify(token, SECRET);
    req.user = payload;
    return next();
  }catch(e){
    return res.status(401).send({error:'invalid token'});
  }
}

app.post('/api/login', (req,res)=>{
  const {email,password} = req.body;
  db.get(`SELECT * FROM users WHERE email = ? AND disabled = 0`, [email], (err,row)=>{
    if (!row) return res.status(401).send({error:'user not found'});
    if (!bcrypt.compareSync(password, row.password)) return res.status(401).send({error:'bad creds'});
    const token = jwt.sign({id: row.id, role: row.role, tenant_id: row.tenant_id, email: row.email}, SECRET, {expiresIn:'8h'});
    res.send({token, role: row.role, tenant_id: row.tenant_id, email: row.email});
  });
});

app.get('/api/admin/tenants', authMiddleware, (req,res)=>{
  if (req.user.role !== 'super_admin') return res.status(403).send({error:'forbidden'});
  db.all(`SELECT t.id, t.name, t.disabled, COUNT(r.id) as rooms_count FROM tenants t LEFT JOIN rooms r ON r.tenant_id = t.id GROUP BY t.id ORDER BY t.id DESC`, [], (err,rows)=>{
    res.send(rows);
  });
});

app.post('/api/admin/create-tenant', authMiddleware, (req,res)=>{
  if (req.user.role !== 'super_admin') return res.status(403).send({error:'forbidden'});
  const {name, adminEmail, roomsCount, country} = req.body;
  db.run(`INSERT INTO tenants (name) VALUES (?)`, [name], function(err){
    if(err) return res.status(500).send({error: 'db error'});
    const tenantId = this.lastID;
    const stmt = db.prepare(`INSERT INTO rooms (tenant_id, number, category, status) VALUES (?,?,?,'Ready')`);
    for(let i=1;i<=roomsCount;i++) stmt.run(tenantId, String(i), 'Standard');
    stmt.finalize();
    const temp = 'Temp@' + Math.random().toString(36).slice(2,8);
    const hash = bcrypt.hashSync(temp, 10);
    db.run(`INSERT INTO users (email,password,role,tenant_id) VALUES (?,?,?,?)`, [adminEmail, hash, 'hotel_admin', tenantId], function(err2){
      if(err2) return res.status(500).send({error:'db error user'});
      db.run(`INSERT INTO history (tenant_id, action, actor, timestamp, details) VALUES (?,?,?,?,?)`, [tenantId, 'created', req.user.email, now(), JSON.stringify({adminEmail,roomsCount,country})]);
      res.send({tenantId, adminEmail, tempPassword: temp});
    });
  });
});

app.post('/api/admin/disable-tenant', authMiddleware, (req,res)=>{
  if (req.user.role !== 'super_admin') return res.status(403).send({error:'forbidden'});
  const {tenantId} = req.body;
  db.run(`UPDATE tenants SET disabled = 1 WHERE id = ?`, [tenantId], function(){
    db.run(`UPDATE users SET disabled = 1 WHERE tenant_id = ?`, [tenantId], ()=>{
      db.run(`INSERT INTO history (tenant_id, action, actor, timestamp, details) VALUES (?,?,?,?,?)`, [tenantId, 'disabled', req.user.email, now(), 'disabled by superadmin']);
      res.send({ok:true});
    });
  });
});

app.post('/api/admin/enable-tenant', authMiddleware, (req,res)=>{
  if (req.user.role !== 'super_admin') return res.status(403).send({error:'forbidden'});
  const {tenantId} = req.body;
  db.run(`UPDATE tenants SET disabled = 0 WHERE id = ?`, [tenantId], function(){
    db.run(`UPDATE users SET disabled = 0 WHERE tenant_id = ?`, [tenantId], ()=>{
      db.run(`INSERT INTO history (tenant_id, action, actor, timestamp, details) VALUES (?,?,?,?,?)`, [tenantId, 'enabled', req.user.email, now(), 'enabled by superadmin']);
      res.send({ok:true});
    });
  });
});

app.get('/api/admin/history', authMiddleware, (req,res)=>{
  if (req.user.role !== 'super_admin') return res.status(403).send({error:'forbidden'});
  const {tenantId} = req.query;
  if (tenantId) {
    db.all(`SELECT * FROM history WHERE tenant_id = ? ORDER BY id DESC`, [tenantId], (err,rows)=> res.send(rows));
  } else {
    db.all(`SELECT * FROM history ORDER BY id DESC LIMIT 200`, [], (err,rows)=> res.send(rows));
  }
});

app.get('/api/rooms', authMiddleware, (req,res)=>{
  const tenant = req.user.tenant_id;
  db.all(`SELECT * FROM rooms WHERE tenant_id = ?`, [tenant], (err,rows)=>{
    res.send(rows);
  });
});

app.post('/api/rooms/:id/update', authMiddleware, (req,res)=>{
  const tenant = req.user.tenant_id;
  const id = req.params.id;
  const {status, notes} = req.body;
  db.get(`SELECT * FROM rooms WHERE id = ? AND tenant_id = ?`, [id, tenant], (err,row)=>{
    if (!row) return res.status(404).send({error:'notfound'});
    db.run(`UPDATE rooms SET status = ?, notes = ? WHERE id = ?`, [status, notes, id], function(){
      db.run(`INSERT INTO history (tenant_id, action, actor, timestamp, details) VALUES (?,?,?,?,?)`, [tenant, 'room_update', req.user.email, now(), JSON.stringify({roomId:id,status,notes})]);
      res.send({ok:true});
    });
  });
});

app.listen(4000, ()=> console.log('Server running on http://localhost:4000'));
