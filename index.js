import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createServer } from 'node:http';
import { Server } from 'socket.io';
import OpenAI from 'openai';
import { respondWithLangChain } from './agents/langchainAgent.js';
import { respondWithRAG } from './agents/ragAgent.js';

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: ['http://localhost:5173', 'http://localhost:5174'], methods: ['GET', 'POST'], credentials: true } });
const PORT = Number(process.env.PORT) || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'development-secret-change-me';
app.use(cors()); app.use(express.json());

const findingSeed = [
  { title: 'Storage account allows public blob access', resource: 'stproddata01', type: 'Storage Account', severity: 'Critical', status: 'Open', framework: 'CIS 3.1.1', recommendation: 'Disable public network access and allow blob access only through approved private endpoints.' },
  { title: 'Network Security Group permits inbound RDP', resource: 'nsg-production-web', type: 'Network Security Group', severity: 'High', status: 'Open', framework: 'CIS 6.1', recommendation: 'Restrict TCP/3389 to a trusted jump host or remove the rule.' },
  { title: 'Key Vault soft delete is disabled', resource: 'kv-payments-prod', type: 'Key Vault', severity: 'Medium', status: 'Open', framework: 'CIS 8.7', recommendation: 'Enable soft delete and purge protection on the vault.' },
  { title: 'SQL server audit logging is configured', resource: 'sql-finance-prod', type: 'SQL Database', severity: 'Low', status: 'Resolved', framework: 'CIS 4.2.1', recommendation: 'No action required. Continue monitoring audit-log retention.' }
];

const generateId = (prefix = 'f') => `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 900 + 100)}`;
const humanRelative = (mins) => (mins < 1 ? 'just now' : mins < 60 ? `${mins} min ago` : `${Math.floor(mins / 60)} hr ago`);
const randomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

function freshFindings() {
  const locations = { stproddata01: 'East US', 'nsg-production-web': 'East US 2', 'kv-payments-prod': 'East US', 'sql-finance-prod': 'West Europe' };
  return findingSeed.map(base => ({
    id: generateId('f'),
    title: base.title,
    resource: base.resource,
    type: base.type,
    severity: base.severity,
    status: base.status,
    framework: base.framework,
    location: locations[base.resource] || 'Azure resource scope',
    updatedAt: humanRelative(randomInt(0, 59)),
    recommendation: base.recommendation
  }));
}

const scanState = { id: generateId('scan'), status: 'Complete', score: 72, lastScan: 'Today, 10:42 AM', resources: 148, findings: freshFindings() };
let telemetryTick = 0;
const liveMetrics = () => {
  telemetryTick += 1;
  const pulse = [0, 1, 0, -1, 0, 1, 0, -1][telemetryTick % 8];
  return {
    score: Math.max(0, Math.min(100, scanState.score + pulse)),
    critical: scanState.findings.filter(f => f.severity === 'Critical' && f.status === 'Open').length,
    compliance: Math.max(0, Math.min(100, 86 + pulse)),
    resources: scanState.resources + (telemetryTick % 3 === 0 ? 1 : 0),
    updatedAt: new Date().toISOString(),
    telemetryMode: 'simulated-live'
  };
};
const users = [];
const cloudApplications = [];
const subscriptions = [{ id: 'sub-prod-001', name: 'Production Azure', tenantId: 'tenant-demo-001', status: 'Connected', lastScan: 'Today, 10:42 AM', resources: 148, security: 'Needs attention' }, { id: 'sub-data-002', name: 'Data Platform', tenantId: 'tenant-demo-001', status: 'Connected', lastScan: 'Yesterday, 4:18 PM', resources: 63, security: 'Healthy' }];
const resources = [{ id: 'res-storage-01', name: 'stproddata01', type: 'Storage Account', group: 'rg-production-data', region: 'East US', subscription: 'Production Azure', status: 'At risk', lastScanned: '2 min ago' }, { id: 'res-vm-01', name: 'vm-production-web', type: 'Virtual Machine', group: 'rg-production-web', region: 'East US 2', subscription: 'Production Azure', status: 'At risk', lastScanned: '2 min ago' }, { id: 'res-sql-01', name: 'sql-finance-prod', type: 'SQL Database', group: 'rg-finance', region: 'West Europe', subscription: 'Data Platform', status: 'Healthy', lastScanned: '18 min ago' }, { id: 'res-nsg-01', name: 'nsg-production-web', type: 'Network Security Group', group: 'rg-production-web', region: 'East US 2', subscription: 'Production Azure', status: 'At risk', lastScanned: '2 min ago' }, { id: 'res-kv-01', name: 'kv-payments-prod', type: 'Key Vault', group: 'rg-production-security', region: 'East US', subscription: 'Production Azure', status: 'At risk', lastScanned: '2 min ago' }];
const controls = [{ id: 'CIS-1.1', name: 'Ensure MFA is enabled for all privileged users', description: 'Privileged identities must use phishing-resistant or multi-factor authentication.', status: 'Fail', affected: 4, severity: 'Critical', remediation: 'Require MFA through Conditional Access for all privileged roles.' }, { id: 'CIS-3.1.1', name: 'Ensure storage accounts restrict public access', description: 'Storage containers should not allow anonymous public blob access.', status: 'Fail', affected: 1, severity: 'Critical', remediation: 'Disable public blob access and use private endpoints.' }, { id: 'CIS-6.1', name: 'Ensure NSG rules do not allow unrestricted RDP', description: 'Inbound management ports must be restricted to approved networks.', status: 'Fail', affected: 1, severity: 'High', remediation: 'Restrict TCP/3389 to a trusted jump host.' }, { id: 'CIS-8.7', name: 'Ensure Key Vault soft delete is enabled', description: 'Secrets must be recoverable after accidental or malicious deletion.', status: 'Pass', affected: 0, severity: 'Medium', remediation: 'Enable soft delete and purge protection.' }, { id: 'CIS-9.1', name: 'Ensure SQL auditing and threat detection are enabled', description: 'Database activity must be logged and monitored.', status: 'Pass', affected: 0, severity: 'High', remediation: 'Enable auditing with a retained Log Analytics destination.' }];
const scanHistory = [{ id: 'scan-1042', date: 'Today, 10:42 AM', subscription: 'Production Azure', resources: 148, findings: 4, critical: 1, compliance: 82, status: 'Complete' }, { id: 'scan-1018', date: 'Yesterday, 4:18 PM', subscription: 'Data Platform', resources: 63, findings: 2, critical: 0, compliance: 88, status: 'Complete' }, { id: 'scan-0927', date: 'Sep 14, 09:27 AM', subscription: 'Production Azure', resources: 145, findings: 7, critical: 2, compliance: 76, status: 'Complete' }];
const alerts = [{ id: 'alert-1', title: 'Public storage access detected', detail: 'stproddata01 permits anonymous blob access.', severity: 'Critical', status: 'Unread', time: '2 min ago' }, { id: 'alert-2', title: 'Unrestricted RDP rule detected', detail: 'nsg-production-web allows inbound TCP/3389.', severity: 'High', status: 'Unread', time: '5 min ago' }, { id: 'alert-3', title: 'Compliance assessment completed', detail: 'CIS Azure Foundations score is 82%.', severity: 'Medium', status: 'Read', time: '18 min ago' }];
const userSchema = new mongoose.Schema({ name: String, email: { type: String, unique: true }, password: String, role: { type: String, default: 'Security Analyst' } }, { timestamps: true });
const User = mongoose.model('User', userSchema);
const cloudApplicationSchema = new mongoose.Schema({ name: String, url: String, provider: { type: String, default: 'Azure' }, owner: String, environment: { type: String, default: 'Production' }, status: { type: String, default: 'Monitoring' }, files: [{ name: String, size: Number, type: String }] }, { timestamps: true });
const CloudApplication = mongoose.model('CloudApplication', cloudApplicationSchema);
let dbReady = false;
if (process.env.MONGODB_URI) mongoose.connect(process.env.MONGODB_URI).then(() => { dbReady = true; console.log('MongoDB connected'); }).catch(() => console.warn('MongoDB unavailable — using demo memory store'));
const publicUser = (u) => ({ id: String(u._id || u.id), name: u.name, email: u.email, role: u.role });
const tokenFor = (u) => jwt.sign({ id: String(u._id || u.id), role: u.role }, JWT_SECRET, { expiresIn: '8h' });
const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); next(); } catch { res.status(401).json({ message: 'Please sign in to continue.' }); } };

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role = 'Security Analyst' } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ message: 'Name, email and a 6+ character password are required.' });
  const existing = dbReady ? await User.findOne({ email }) : users.find((u) => u.email === email);
  if (existing) return res.status(409).json({ message: 'An account already exists for that email.' });
  const user = { id: crypto.randomUUID(), name, email, password: await bcrypt.hash(password, 12), role };
  if (dbReady) { const saved = await User.create(user); return res.status(201).json({ token: tokenFor(saved), user: publicUser(saved) }); }
  users.push(user); res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
});
app.post('/api/auth/login', async (req, res) => {
  const user = dbReady ? await User.findOne({ email: req.body.email }) : users.find((u) => u.email === req.body.email);
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(401).json({ message: 'Invalid email or password.' });
  res.json({ token: tokenFor(user), user: publicUser(user) });
});
app.get('/api/dashboard', auth, (req, res) => res.json({ ...scanState, ...liveMetrics(), trend: [58, 61, 64, 63, 68, 72] }));
app.get('/api/findings', auth, (req, res) => { const q = (req.query.search || '').toLowerCase(); const severity = req.query.severity; res.json(scanState.findings.filter(f => (!q || Object.values(f).join(' ').toLowerCase().includes(q)) && (!severity || f.severity === severity))); });
app.get('/api/subscriptions', auth, (req, res) => res.json(subscriptions));
app.post('/api/subscriptions', auth, (req, res) => { const { name, subscriptionId, tenantId } = req.body; if (!name || !subscriptionId || !tenantId) return res.status(400).json({ message: 'Subscription name, subscription ID, and tenant ID are required.' }); const subscription = { id: subscriptionId, name, tenantId, status: 'Connected', lastScan: 'Never', resources: 0, security: 'Not scanned' }; subscriptions.unshift(subscription); res.status(201).json(subscription); });
app.get('/api/resources', auth, (req, res) => { const q = (req.query.search || '').toLowerCase(); res.json(resources.filter(resource => !q || Object.values(resource).join(' ').toLowerCase().includes(q))); });
app.get('/api/controls', auth, (req, res) => res.json(controls));
app.get('/api/scans/history', auth, (req, res) => res.json(scanHistory));
app.get('/api/alerts', auth, (req, res) => res.json(alerts));
app.patch('/api/alerts/:id', auth, (req, res) => { const alert = alerts.find(item => item.id === req.params.id); if (!alert) return res.status(404).json({ message: 'Alert not found.' }); alert.status = req.body.status || 'Read'; res.json(alert); });
app.get('/api/reports', auth, (req, res) => res.json([{ id: 'report-security', name: 'Security Audit Report', type: 'Security', generated: 'Today, 10:45 AM', status: 'Ready' }, { id: 'report-compliance', name: 'CIS Compliance Report', type: 'Compliance', generated: 'Today, 10:45 AM', status: 'Ready' }, { id: 'report-risk', name: 'Risk Assessment Report', type: 'Risk', generated: 'Yesterday, 4:20 PM', status: 'Ready' }]));
app.get('/api/users', auth, async (req, res) => { const list = dbReady ? await User.find().select('name email role createdAt updatedAt') : users; res.json(list.map(item => ({ id: String(item._id || item.id), name: item.name, email: item.email, role: item.role, status: 'Active', lastLogin: 'Today, 10:42 AM', createdAt: item.createdAt || 'Today' }))); });
app.get('/api/cloud-applications', auth, async (req, res) => { const applications = dbReady ? await CloudApplication.find().sort({ createdAt: -1 }) : cloudApplications; res.json(applications); });
app.post('/api/cloud-applications', auth, async (req, res) => {
  const { name, url, provider = 'Azure', owner = req.user.id, environment = 'Production', files = [] } = req.body;
  if (!name || !url) return res.status(400).json({ message: 'Application name and deployment URL are required.' });
  try { new URL(url); } catch { return res.status(400).json({ message: 'Enter a valid deployment URL.' }); }
  const record = { name, url, provider, owner, environment, status: 'Monitoring', files: files.slice(0, 20), createdAt: new Date().toISOString() };
  if (dbReady) return res.status(201).json(await CloudApplication.create(record));
  const saved = { id: generateId('app'), ...record }; cloudApplications.unshift(saved); res.status(201).json(saved);
});
app.patch('/api/findings/:id', auth, (req, res) => { const finding = scanState.findings.find(f => f.id === req.params.id); if (!finding) return res.status(404).json({ message: 'Finding not found.' }); finding.status = req.body.status || finding.status; finding.updatedAt = 'just now'; io.emit('finding:updated', finding); res.json(finding); });
app.post('/api/scans', auth, (req, res) => {
  if (scanState.status === 'Scanning') return res.status(409).json({ message: 'A scan is already running.' });
  scanState.status = 'Scanning'; let progress = 0; io.emit('scan:progress', { progress, status: 'Discovering Azure resources' });
  const timer = setInterval(() => { progress += 20; io.emit('scan:progress', { progress, status: progress < 60 ? 'Evaluating CIS controls' : 'Calculating risk score' }); if (progress >= 100) { clearInterval(timer); scanState.status = 'Complete'; scanState.lastScan = 'just now'; scanState.score = 74; io.emit('scan:complete', scanState); } }, 700);
  res.status(202).json({ message: 'Security scan started.' });
});
app.post('/api/url-assessments', auth, (req, res) => {
  let target;
  try { target = new URL(req.body.url); } catch { return res.status(400).json({ message: 'Enter a valid URL (e.g. http://, https://).' }); }

  const allowedProtocols = ['http:', 'https:'];
  const adminProtocols = ['ftp:', 'sftp:', 'ssh:', 'smtp:'];
  const permitted = allowedProtocols.concat(req.user.role === 'Administrator' ? adminProtocols : []);

  if (!permitted.includes(target.protocol)) {
    return res.status(400).json({
      message: req.user.role === 'Administrator'
        ? 'Only HTTP(S), FTP, SFTP, SSH, or SMTP URLs can be assessed for administrators.'
        : 'Only HTTP(S) URLs can be assessed.'
    });
  }

  const host = target.hostname.replace(/^www\./, '');
  const safeId = host.replace(/[^a-z0-9]/gi, '-').slice(0, 28);
  const assessment = [
    { id: `url-${safeId}-headers`, title: 'Security-header policy needs verification', resource: host, location: host, type: 'Web Application', severity: 'Medium', status: 'Open', framework: 'OWASP A05', updatedAt: 'just now', targetUrl: target.href, recommendation: 'Configure a strict Content-Security-Policy, HSTS and frame-ancestors policy, then validate them in your deployment environment.' },
    { id: `url-${safeId}-secrets`, title: 'Client-side secret exposure review required', resource: host, location: host, type: 'Web Application', severity: 'High', status: 'Open', framework: 'OWASP A02', updatedAt: 'just now', targetUrl: target.href, recommendation: 'Keep credentials in server-side environment variables, rotate any exposed keys, and ensure .env files are excluded from version control.' }
  ];
  assessment.forEach(finding => { const index = scanState.findings.findIndex(f => f.id === finding.id); if (index >= 0) scanState.findings[index] = finding; else scanState.findings.unshift(finding); });
  io.emit('finding:updated', assessment[0]);
  res.status(201).json({ message: `Defensive project assessment created for ${host}.`, targetUrl: target.href, findings: assessment, simulated: true });
});
app.post('/api/assistant', auth, async (req, res) => {
  const prompt = req.body.message?.trim();
  if (!prompt) return res.status(400).json({ message: 'Ask the assistant a security question.' });

  // If the user asks about breaches, return a simulated global open finding (randomized id/time)
  const breachRe = /breach|breached|breaches|breaching|compromise|leak/i;
  if (breachRe.test(prompt)) {
    const finding = {
      id: generateId('g'),
      title: 'Publicly exposed database containing credentials and PII',
      resource: `exposed-db-${Math.floor(Math.random() * 9000 + 1000)}`,
      location: 'global',
      severity: 'Critical',
      status: 'Open',
      discoveredAt: new Date().toISOString(),
      updatedAt: humanRelative(randomInt(0, 120)),
      recommendation: 'Isolate the resource, rotate all affected credentials, revoke keys, expedite a forensics review, notify impacted parties per law, and apply least-privilege network controls (VPC, private endpoints).' 
    };
    const answer = `Simulated global finding detected: ${finding.title} on resource ${finding.resource}. Severity: ${finding.severity}. Recommended remediation: ${finding.recommendation}`;
    return res.json({ source: 'simulated-global-finding', answer, finding });
  }

  if (process.env.OPENAI_API_KEY) {
    try {
      const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
      const answer = await client.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'system', content: 'You are a concise Azure CSPM security analyst. Give defensive, actionable remediation advice only.' }, { role: 'user', content: prompt }], max_tokens: 300 });
      return res.json({ answer: answer.choices[0].message.content, source: 'AI' });
    } catch { /* fall through */ }
  }

  const relevant = findingSeed.find(f => `${f.title} ${f.resource} ${f.framework}`.toLowerCase().split(' ').some(w => w.length > 4 && prompt.toLowerCase().includes(w)));
  res.json({ source: 'Local security guidance', answer: relevant ? `For ${relevant.resource}: ${relevant.recommendation} This addresses ${relevant.framework} and should be validated in the next scan.` : 'Prioritize Critical and High findings first. Verify public network exposure, enforce least privilege, enable diagnostic logs, and re-run the scan after each remediation.' });
});

// LangChain agent endpoint (supports OpenAI or local llama via env)
app.post('/api/agent/langchain', auth, async (req, res) => {
  const prompt = (req.body.message || req.body.prompt || '').toString().trim();
  if (!prompt) return res.status(400).json({ message: 'Prompt is required.' });
  try {
    const answer = await respondWithLangChain(prompt, { modelName: req.body.model });
    return res.json({ source: process.env.USE_LOCAL_LLAMA === '1' ? 'local-llama' : 'openai-langchain', answer });
  } catch (err) {
    console.error('LangChain agent error:', err?.message || err);
    return res.status(500).json({ message: err?.message || 'Agent error' });
  }
});

app.post('/api/agent/rag', auth, async (req, res) => {
  const prompt = (req.body.message || req.body.prompt || '').toString().trim();
  if (!prompt) return res.status(400).json({ message: 'Prompt is required.' });
  try {
    const answer = await respondWithRAG(prompt, { modelName: req.body.model });
    return res.json({ source: 'openai-rag', answer });
  } catch (err) {
    console.error('RAG agent error:', err?.message || err);
    return res.status(500).json({ message: err?.message || 'RAG error' });
  }
});
setInterval(() => { io.emit('telemetry:update', liveMetrics()); scanState.findings = freshFindings(); io.emit('breaches:update', { findings: scanState.findings, updatedAt: new Date().toISOString() }); }, 1000).unref();
io.on('connection', socket => { socket.emit('scan:state', scanState); socket.emit('telemetry:update', liveMetrics()); });
httpServer.listen(PORT, () => console.log(`CSPM API listening on :${PORT}`));
