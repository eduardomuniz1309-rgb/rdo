import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// DB
sqlite3.verbose();
const db = new sqlite3.Database(path.join(__dirname, 'data.sqlite'));
db.serialize(()=>{ db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','user'))
);`); });

function dbGet(sql, params=[]) { return new Promise((resolve,reject)=> db.get(sql, params, (e,r)=> e?reject(e):resolve(r))); }
function dbAll(sql, params=[]) { return new Promise((resolve,reject)=> db.all(sql, params, (e,r)=> e?reject(e):resolve(r))); }
function dbRun(sql, params=[]) { return new Promise((resolve,reject)=> db.run(sql, params, function(e){ e?reject(e):resolve(this); })); }

async function usersCount(){ const r = await dbGet('SELECT COUNT(*) c FROM users'); return r?.c||0; }
function signToken(u){ return jwt.sign({ id:u.id, role:u.role, name:u.name, email:u.email }, JWT_SECRET, { expiresIn:'8h' }); }
function authRequired(req,res,next){ try{ const a=req.headers.authorization||''; const t=a.startsWith('Bearer ')?a.slice(7):null; if(!t) return res.status(401).json({error:'unauthorized'}); req.user=jwt.verify(t, JWT_SECRET); next(); }catch(e){ return res.status(401).json({error:'invalid_token'});} }
function adminOnly(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'forbidden'}); next(); }

app.post('/api/auth/register', async (req,res)=>{ try{ const {name,email,password,role} = req.body||{}; if(!name||!email||!password) return res.status(400).json({error:'missing_fields'}); const count=await usersCount(); if(count>0){ try{ authRequired(req,res,()=>{}); }catch(e){ return; } if(!req.user||req.user.role!=='admin') return res.status(403).json({error:'forbidden'}); } const hash=await bcrypt.hash(password,10); const r=(count===0)?'admin':(role==='admin'?'admin':'user'); await dbRun('INSERT INTO users(name,email,password_hash,role) VALUES (?,?,?,?)',[name.trim(),email.trim().toLowerCase(),hash,r]); const u=await dbGet('SELECT id,name,email,role FROM users WHERE email=?',[email.trim().toLowerCase()]); return res.json({ok:true,user:u}); }catch(err){ if(String(err).includes('UNIQUE')) return res.status(400).json({error:'email_in_use'}); console.error(err); return res.status(500).json({error:'server_error'});} });

app.post('/api/auth/login', async (req,res)=>{ try{ const {email,password}=req.body||{}; if(!email||!password) return res.status(400).json({error:'missing_fields'}); const u=await dbGet('SELECT * FROM users WHERE email=?',[email.trim().toLowerCase()]); if(!u) return res.status(401).json({error:'invalid_credentials'}); const ok=await bcrypt.compare(password,u.password_hash); if(!ok) return res.status(401).json({error:'invalid_credentials'}); const token=signToken(u); return res.json({token, user:{id:u.id,name:u.name,email:u.email,role:u.role}}); }catch(err){ console.error(err); return res.status(500).json({error:'server_error'});} });

app.get('/api/auth/me', authRequired, async (req,res)=> res.json({user:req.user}));
app.get('/api/users', authRequired, adminOnly, async (req,res)=>{ const rows=await dbAll('SELECT id,name,email,role FROM users ORDER BY id ASC'); res.json({users:rows}); });
app.post('/api/users', authRequired, adminOnly, async (req,res)=>{ try{ const {name,email,password,role}=req.body||{}; if(!name||!email||!password) return res.status(400).json({error:'missing_fields'}); const hash=await bcrypt.hash(password,10); await dbRun('INSERT INTO users(name,email,password_hash,role) VALUES (?,?,?,?)',[name.trim(),email.trim().toLowerCase(),hash, role==='admin'?'admin':'user']); res.json({ok:true}); }catch(err){ if(String(err).includes('UNIQUE')) return res.status(400).json({error:'email_in_use'}); console.error(err); res.status(500).json({error:'server_error'});} });
app.delete('/api/users/:id', authRequired, adminOnly, async (req,res)=>{ try{ const id=Number(req.params.id); const u=await dbGet('SELECT * FROM users WHERE id=?',[id]); if(!u) return res.status(404).json({error:'not_found'}); if(u.role==='admin'){ const n=await dbGet("SELECT COUNT(*) c FROM users WHERE role='admin'"); if((n?.c||0)<=1) return res.status(400).json({error:'cannot_remove_last_admin'}); } await dbRun('DELETE FROM users WHERE id=?',[id]); res.json({ok:true}); }catch(err){ console.error(err); res.status(500).json({error:'server_error'});} });

app.use(express.static(path.join(__dirname,'public')));
app.get('/', (req,res)=> res.redirect('/login.html'));
app.listen(PORT, ()=> console.log(`Server listening on http://localhost:${PORT}`));
