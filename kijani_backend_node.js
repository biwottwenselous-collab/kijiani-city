// Kijani Project - Backend
// This single-file package lists all project files and their contents. Create these files in a folder to run the backend.

/////////////////////////////////////////////
// File: package.json
/////////////////////////////////////////////
{
  "name": "kijani-backend",
  "version": "1.0.0",
  "description": "Backend API for the Kijani project (Node.js, Express, Sequelize, PostgreSQL)",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "body-parser": "^1.20.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "pg": "^8.11.1",
    "pg-hstore": "^2.3.4",
    "sequelize": "^6.32.1"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}

/////////////////////////////////////////////
// File: .env.example
/////////////////////////////////////////////
# Copy to .env and fill values
PORT=4000
DATABASE_URL=postgres://user:password@localhost:5432/kijani_db
JWT_SECRET=replace_with_a_long_secret
BCRYPT_SALT_ROUNDS=10

/////////////////////////////////////////////
// File: config/database.js
/////////////////////////////////////////////
const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectOptions: {
    // Add ssl config if needed in production
    // ssl: { require: true, rejectUnauthorized: false }
  }
});

module.exports = sequelize;

/////////////////////////////////////////////
// File: models/User.js
/////////////////////////////////////////////
const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/database');

class User extends Model {}

User.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  passwordHash: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('admin','user'), defaultValue: 'user' }
}, { sequelize, modelName: 'user' });

module.exports = User;

/////////////////////////////////////////////
// File: models/Project.js
/////////////////////////////////////////////
const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/database');
const User = require('./User');

class Project extends Model {}

Project.init({
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  title: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT },
  metadata: { type: DataTypes.JSONB, defaultValue: {} }
}, { sequelize, modelName: 'project' });

Project.belongsTo(User, { as: 'owner', foreignKey: 'ownerId' });
User.hasMany(Project, { foreignKey: 'ownerId' });

module.exports = Project;

/////////////////////////////////////////////
// File: middleware/auth.js
/////////////////////////////////////////////
const jwt = require('jsonwebtoken');
require('dotenv').config();
const User = require('../models/User');

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'Missing Authorization header' });

  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Invalid Authorization format' });

  const token = parts[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findByPk(payload.sub);
    if (!user) return res.status(401).json({ message: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

module.exports = authMiddleware;

/////////////////////////////////////////////
// File: routes/auth.js
/////////////////////////////////////////////
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const User = require('../models/User');

// Register
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
  try {
    const existing = await User.findOne({ where: { email } });
    if (existing) return res.status(409).json({ message: 'Email already in use' });
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10');
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const user = await User.create({ name, email, passwordHash });
    return res.status(201).json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Missing fields' });
  try {
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

/////////////////////////////////////////////
// File: routes/projects.js
/////////////////////////////////////////////
const express = require('express');
const router = express.Router();
const Project = require('../models/Project');
const auth = require('../middleware/auth');

// Get all projects (public minimal info)
router.get('/', async (req, res) => {
  const list = await Project.findAll({ attributes: ['id','title','description'] });
  res.json(list);
});

// Create project
router.post('/', auth, async (req, res) => {
  const { title, description, metadata } = req.body;
  if (!title) return res.status(400).json({ message: 'Missing title' });
  const project = await Project.create({ title, description, metadata, ownerId: req.user.id });
  res.status(201).json(project);
});

// Get single project
router.get('/:id', async (req, res) => {
  const project = await Project.findByPk(req.params.id);
  if (!project) return res.status(404).json({ message: 'Not found' });
  res.json(project);
});

// Update (owner only)
router.put('/:id', auth, async (req, res) => {
  const project = await Project.findByPk(req.params.id);
  if (!project) return res.status(404).json({ message: 'Not found' });
  if (project.ownerId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { title, description, metadata } = req.body;
  project.title = title ?? project.title;
  project.description = description ?? project.description;
  project.metadata = metadata ?? project.metadata;
  await project.save();
  res.json(project);
});

// Delete (owner or admin)
router.delete('/:id', auth, async (req, res) => {
  const project = await Project.findByPk(req.params.id);
  if (!project) return res.status(404).json({ message: 'Not found' });
  if (project.ownerId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await project.destroy();
  res.json({ message: 'Deleted' });
});

module.exports = router;

/////////////////////////////////////////////
// File: app.js
/////////////////////////////////////////////
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();
const sequelize = require('./config/database');
const User = require('./models/User');
const Project = require('./models/Project');

const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);

app.get('/', (req, res) => res.json({ message: 'Kijani backend running' }));

async function start() {
  try {
    await sequelize.authenticate();
    // Sync models - in production use migrations
    await sequelize.sync({ alter: true });
    const port = process.env.PORT || 4000;
    app.listen(port, () => console.log(`Server listening on port ${port}`));
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
}

start();

/////////////////////////////////////////////
// File: README.md
/////////////////////////////////////////////
# Kijani Backend (Node.js + Express)

## Overview
This repository contains a simple REST API for the Kijani project using Node.js, Express and PostgreSQL (via Sequelize). It supports user registration/login (JWT) and a simple Project resource with ownership.

## Quick start
1. Create a new folder and add the files from this document (preserving file names and folder structure).
2. Copy `.env.example` to `.env` and fill values.
3. Ensure PostgreSQL is running and `DATABASE_URL` points to a valid DB.
4. Install dependencies:

```bash
npm install
```

5. Start the app:

```bash
npm run dev
```

6. API endpoints:
- `POST /api/auth/register` {name,email,password}
- `POST /api/auth/login` {email,password} -> returns `{token}`
- `GET /api/projects`
- `POST /api/projects` (auth)
- `GET /api/projects/:id`
- `PUT /api/projects/:id` (auth / owner)
- `DELETE /api/projects/:id` (auth / owner)

## Notes
- This is a minimal starting point. Add validation, request rate-limiting, logging, proper error handling, tests, migrations, and HTTPS in production.
- For cloud deployment consider Dockerizing and using a managed database.

/////////////////////////////////////////////
// End of listing
/////////////////////////////////////////////
