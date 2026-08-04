/**
 * FC3D 会员认证系统 - Vercel Edge Function
 * 从 Cloudflare Worker 迁移而来
 * 
 * API 端点:
 *   POST /api/register      → 注册
 *   POST /api/login          → 登录
 *   GET  /api/me             → 获取当前用户
 *   POST /api/admin/set-vip  → 设置VIP等级（需admin）
 *   GET  /api/admin/users    → 用户列表（需admin）
 *   GET  /api/health         → 健康检查
 * 
 * 存储: Vercel KV (Upstash Redis)
 */

import { kv } from '@vercel/kv';

const ADMIN_EMAIL = 'sujin-feng@coze.email';
const TOKEN_TTL = 7 * 24 * 60 * 60;
const KV_PREFIX = 'user:';
const JWT_SECRET = process.env.JWT_SECRET || 'fc3d_webapp_jwt_secret_2026_secure_key_xk9m2p';

const CORS_ORIGINS = [
  'https://lxf-ecom.github.io',
  'http://localhost:3000', 'http://127.0.0.1:3000',
  'http://localhost:5173', 'http://127.0.0.1:5173',
];

// ========== 工具函数 ==========

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(key, message) {
  const enc = new TextEncoder();
  const keyData = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', keyData, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64url(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; return atob(str); }

async function generateToken(email, vipLevel) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({ email, vip_level: vipLevel, iat: now, exp: now + TOKEN_TTL }));
  const sig = await hmacSha256(JWT_SECRET, `${header}.${payload}`);
  return `${header}.${payload}.${sig}`;
}

async function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expected = await hmacSha256(JWT_SECRET, `${header}.${payload}`);
  if (signature !== expected) return null;
  try {
    const data = JSON.parse(b64urlDecode(payload));
    if (data.exp && data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch { return null; }
}

function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }

function extractToken(req) {
  const auth = req.headers.get('Authorization');
  return auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function corsHeaders(req) {
  const origin = req.headers.get('Origin') || '';
  return {
    'Access-Control-Allow-Origin': CORS_ORIGINS.includes(origin) ? origin : 'https://lxf-ecom.github.io',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResp(data, status = 200, req = null) {
  const h = { 'Content-Type': 'application/json; charset=utf-8' };
  if (req) Object.assign(h, corsHeaders(req));
  return new Response(JSON.stringify(data), { status, headers: h });
}

function safeUser(u) {
  return { email: u.email, nickname: u.nickname || u.email.split('@')[0], vip_level: u.vip_level || 'free', created_at: u.created_at || '', last_login: u.last_login || '' };
}

// ========== KV 封装（兼容 Vercel KV） ==========

async function kvGet(key) {
  const v = await kv.get(key);
  if (v === null || v === undefined) return null;
  return typeof v === 'string' ? v : JSON.stringify(v);
}

async function kvSet(key, value) { await kv.set(key, value); }

async function kvListKeys(prefix) { return await kv.keys({ prefix, count: 1000 }); }

// ========== 路由 ==========

async function handleRegister(req) {
  let body; try { body = await req.json(); } catch { return jsonResp({ success: false, error: '无效的请求体' }, 400, req); }
  const { email, password, nickname } = body;
  if (!email || !password) return jsonResp({ success: false, error: '邮箱和密码不能为空' }, 400, req);
  if (!isValidEmail(email)) return jsonResp({ success: false, error: '邮箱格式不正确' }, 400, req);
  if (password.length < 6) return jsonResp({ success: false, error: '密码至少6位' }, 400, req);

  const ne = email.toLowerCase().trim();
  const k = KV_PREFIX + ne;
  if (await kvGet(k)) return jsonResp({ success: false, error: '该邮箱已注册' }, 409, req);

  const salt = generateSalt();
  const ph = await sha256(salt + password);
  const vl = ne === ADMIN_EMAIL ? 'admin' : 'free';
  const now = new Date().toISOString();
  const user = { email: ne, nickname: (nickname || ne.split('@')[0]).substring(0, 20), password_hash: ph, salt, vip_level: vl, created_at: now, last_login: now };

  await kvSet(k, JSON.stringify(user));
  const token = await generateToken(ne, vl);
  return jsonResp({ success: true, message: '注册成功', token, user: safeUser(user) }, 201, req);
}

async function handleLogin(req) {
  let body; try { body = await req.json(); } catch { return jsonResp({ success: false, error: '无效的请求体' }, 400, req); }
  const { email, password } = body;
  if (!email || !password) return jsonResp({ success: false, error: '邮箱和密码不能为空' }, 400, req);

  const ne = email.toLowerCase().trim();
  const k = KV_PREFIX + ne;
  const raw = await kvGet(k);
  if (!raw) return jsonResp({ success: false, error: '邮箱或密码错误' }, 401, req);

  const user = JSON.parse(raw);
  if (await sha256(user.salt + password) !== user.password_hash) return jsonResp({ success: false, error: '邮箱或密码错误' }, 401, req);

  user.last_login = new Date().toISOString();
  await kvSet(k, JSON.stringify(user));
  const token = await generateToken(ne, user.vip_level);
  return jsonResp({ success: true, message: '登录成功', token, user: safeUser(user) }, 200, req);
}

async function handleMe(req) {
  const token = extractToken(req);
  if (!token) return jsonResp({ success: false, error: '未提供认证令牌' }, 401, req);
  const p = await verifyToken(token);
  if (!p) return jsonResp({ success: false, error: '令牌无效或已过期' }, 401, req);

  const raw = await kvGet(KV_PREFIX + p.email);
  if (!raw) return jsonResp({ success: false, error: '用户不存在' }, 404, req);
  return jsonResp({ success: true, user: safeUser(JSON.parse(raw)) }, 200, req);
}

async function handleAdminSetVip(req) {
  const token = extractToken(req);
  if (!token) return jsonResp({ success: false, error: '未提供认证令牌' }, 401, req);
  const p = await verifyToken(token);
  if (!p) return jsonResp({ success: false, error: '令牌无效或已过期' }, 401, req);
  if (p.vip_level !== 'admin') return jsonResp({ success: false, error: '无管理员权限' }, 403, req);

  let body; try { body = await req.json(); } catch { return jsonResp({ success: false, error: '无效的请求体' }, 400, req); }
  const { email, vip_level } = body;
  if (!email || !vip_level) return jsonResp({ success: false, error: '邮箱和VIP等级不能为空' }, 400, req);
  if (!['free', 'vip1', 'vip2', 'admin'].includes(vip_level)) return jsonResp({ success: false, error: '无效的VIP等级' }, 400, req);

  const k = KV_PREFIX + email.toLowerCase().trim();
  const raw = await kvGet(k);
  if (!raw) return jsonResp({ success: false, error: '未找到该用户' }, 404, req);

  const user = JSON.parse(raw);
  user.vip_level = vip_level;
  await kvSet(k, JSON.stringify(user));
  return jsonResp({ success: true, message: `已设置 ${email} 为 ${vip_level}`, user: safeUser(user) }, 200, req);
}

async function handleAdminUsers(req) {
  const token = extractToken(req);
  if (!token) return jsonResp({ success: false, error: '未提供认证令牌' }, 401, req);
  const p = await verifyToken(token);
  if (!p || p.vip_level !== 'admin') return jsonResp({ success: false, error: '无管理员权限' }, 403, req);

  const keys = await kvListKeys(KV_PREFIX);
  const users = [];
  for (const key of keys) {
    const raw = await kvGet(key.name);
    if (raw) { try { users.push(safeUser(JSON.parse(raw))); } catch {} }
  }
  users.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  return jsonResp({ success: true, users, total: users.length }, 200, req);
}

async function handleHealth(req) {
  return jsonResp({ success: true, status: 'ok', timestamp: new Date().toISOString(), service: 'FC3D Auth API (Vercel Edge)', version: '2.0.0' }, 200, req);
}

// ========== 主入口 ==========

export default async function handler(request) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request) });

  const url = new URL(request.url);
  const p = url.pathname, m = request.method;

  try {
    if (p === '/api/health' && m === 'GET') return await handleHealth(request);
    if (p === '/api/register' && m === 'POST') return await handleRegister(request);
    if (p === '/api/login' && m === 'POST') return await handleLogin(request);
    if (p === '/api/me' && m === 'GET') return await handleMe(request);
    if (p === '/api/admin/set-vip' && m === 'POST') return await handleAdminSetVip(request);
    if (p === '/api/admin/users' && m === 'GET') return await handleAdminUsers(request);
    return jsonResp({ success: false, error: '接口不存在', path: p }, 404, request);
  } catch (err) {
    console.error('Unhandled error:', err);
    return jsonResp({ success: false, error: '服务器内部错误' }, 500, request);
  }
}

export const config = { runtime: 'edge' };
