const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || Buffer.byteLength(jwtSecret) < 32) {
  throw new Error('JWT_SECRET must be set to a secret of at least 32 bytes.');
}

const app = express();
const PORT = 3000;
const allowedOrigins = new Set([
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:5501',
  'http://127.0.0.1:5501'
]);

const accountSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, select: false }
});
const Account = mongoose.model('account', accountSchema);

const taskSchema = new mongoose.Schema({
  task_name: { type: String, required: true },
  deadline: { type: String, required: true },
  category: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'account', required: true, select: false }
});
const Task = mongoose.model('todo', taskSchema);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true);
      return;
    }
    callback(null, false);
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function isValidCredentials(body) {
  return body !== null &&
    typeof body === 'object' &&
    !Array.isArray(body) &&
    typeof body.email === 'string' &&
    typeof body.password === 'string';
}

function validateCredentials(email, password) {
  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return 'A valid email address is required.';
  }
  if (password.length < 8 || Buffer.byteLength(password) > 72) {
    return 'Password must be at least 8 characters and no more than 72 bytes.';
  }
  return null;
}

function createToken(userId) {
  return jwt.sign({ sub: userId.toString() }, jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '1h'
  });
}

function authenticate(req, res, next) {
  const authorization = req.get('Authorization');
  const match = authorization && authorization.match(/^Bearer\s+(\S+)$/i);
  if (!match) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  try {
    const payload = jwt.verify(match[1], jwtSecret, { algorithms: ['HS256'] });
    if (typeof payload === 'string' || typeof payload.sub !== 'string') {
      res.status(401).json({ error: 'Invalid or expired token.' });
      return;
    }
    req.userId = payload.sub;
    next();
  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
      res.status(401).json({ error: 'Invalid or expired token.' });
      return;
    }
    next(err);
  }
}

app.post('/auth/register', async (req, res) => {
  if (!isValidCredentials(req.body)) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const email = req.body.email.trim().toLowerCase();
  const passwordError = validateCredentials(email, req.body.password);
  if (passwordError) {
    res.status(400).json({ error: passwordError });
    return;
  }

  try {
    const password = await bcrypt.hash(req.body.password, 12);
    const account = await Account.create({ email, password });
    res.status(201).json({
      token: createToken(account._id),
      user: { id: account._id.toString(), email: account.email }
    });
  } catch (err) {
    if (err.code === 11000) {
      res.status(409).json({ error: 'An account with this email already exists.' });
      return;
    }
    console.error('Registration failed.');
    res.status(500).json({ error: 'Unable to register account.' });
  }
});

app.post('/auth/login', async (req, res) => {
  if (!isValidCredentials(req.body)) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const email = req.body.email.trim().toLowerCase();
  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: 'A valid email address is required.' });
    return;
  }
  try {
    const account = await Account.findOne({ email }).select('+password');
    if (Buffer.byteLength(req.body.password) > 72 ||
        !account ||
        !(await bcrypt.compare(req.body.password, account.password))) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    res.json({
      token: createToken(account._id),
      user: { id: account._id.toString(), email: account.email }
    });
  } catch (err) {
    console.error('Login failed.');
    res.status(500).json({ error: 'Unable to log in.' });
  }
});

app.post('/', authenticate, async (req, res) => {
  const { task_name, deadline, category } = req.body || {};
  if ([task_name, deadline, category].some(value => typeof value !== 'string' || !value.trim())) {
    res.status(400).json({ error: 'task_name, deadline, and category are required.' });
    return;
  }

  try {
    const task = await Task.create({
      task_name: task_name.trim(),
      deadline: deadline.trim(),
      category: category.trim(),
      userId: req.userId
    });
    const taskResponse = task.toObject();
    delete taskResponse.userId;
    res.status(201).json(taskResponse);
  } catch (err) {
    console.error('Task creation failed.');
    res.status(500).json({ error: 'Unable to create task.' });
  }
});

app.get('/all-task', authenticate, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.userId });
    console.log(tasks)
    res.json(tasks);
  } catch (err) {
    console.error('Task retrieval failed.');
    res.status(500).json({ error: 'Unable to retrieve tasks.' });
  }
});

app.delete('/delete/:task_name', authenticate, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({
      task_name: req.params.task_name,
      userId: req.userId
    });
    if (!task) {
      res.status(404).json({ error: 'Task not found.' });
      return;
    }
    res.json({ message: 'Task deleted.' });
  } catch (err) {
    console.error('Task deletion failed.');
    res.status(500).json({ error: 'Unable to delete task.' });
  }
});

app.put('/update/:task_name', authenticate, async (req, res) => {
  const updates = {};
  for (const field of ['task_name', 'deadline', 'category']) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
      if (typeof req.body[field] !== 'string' || !req.body[field].trim()) {
        res.status(400).json({ error: `${field} must be a non-empty string.` });
        return;
      }
      updates[field] = req.body[field].trim();
    }
  }
  if (Object.keys(updates).length === 0) {
    res.status(400).json({ error: 'At least one task field must be provided.' });
    return;
  }

  try {
    const task = await Task.findOneAndUpdate(
      { task_name: req.params.task_name, userId: req.userId },
      { $set: updates },
      { new: true, runValidators: true }
    );
    if (!task) {
      res.status(404).json({ error: 'Task not found.' });
      return;
    }
    res.json(task);
  } catch (err) {
    console.error('Task update failed.');
    res.status(500).json({ error: 'Unable to update task.' });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    res.status(400).json({ error: 'Request body contains invalid JSON.' });
    return;
  }
  console.error('Request failed.');
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

async function startServer() {
  try {
    await mongoose.connect(process.env.url);
    await Account.init();
    console.log('MongoDB Connected');
    app.listen(PORT, () => {
      console.log(`Server is listening at http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Unable to connect to MongoDB.');
    process.exitCode = 1;
  }
}

startServer();
