// Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const dotenv = require('dotenv');
const cors = require('cors');
dotenv.config();

const app = express();
// Allow requests from specific origin
app.use(cors({
    origin: 'http://localhost:3000', // Frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE','PATCH'], // Allowed HTTP methods
    credentials: true, // Include credentials like cookies
}));
app.use(express.json());

const path = require('path');

// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    address: { type: String },
    role: { type: String, enum: ['PhD Student', 'Researcher', 'Admin'], required: true },
    bio: { type: String },
    image: { type: String },
    timeline: [{
        institution: String,
        degree: String,
        startDate: Date,
        endDate: Date,
    }],
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
});

const publicationSchema = new mongoose.Schema({
    title: { type: String, required: true },
    authors: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
    additionalAuthors: [{ type: String }], // Renamed from unregistered_authors
    summary: { type: String },
    coverImage: { type: String },
    doi: { type: String },
    year: { type: Number, default: () => new Date().getFullYear() }, // Automatically set to current year
}, { timestamps: true }); // Optional: Adds createdAt and updatedAt fields


const teamSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

// ====================
// 1) ADDRESS MODEL + ROUTES
// ====================
const addressSchema = new mongoose.Schema({
  room: String,
  department: String,
  institution: String,
  city: String,
  state: String,
  postalCode: String,
  country: String
});


// ====================
// 2) ROLE MODEL + ROUTES
// ====================

const roleSchema = new mongoose.Schema({
  roleName: String // e.g. "PhD Student", "Scholar", "Researcher"
});


// ====================
// 3) RESOURCETEXT MODEL + ROUTES
// ====================

const resourceTextSchema = new mongoose.Schema({
  text: String // Could be a large string 
});

// ====================
// 4) TECHNOLOGY MODEL + ROUTES
// ====================

const technologySchema = new mongoose.Schema({
  name: String,
  icon: String,         // e.g. URL or path to icon
  description: String,
  downloadLink: String  // e.g. link to .zip or PDF
});

// ====================
// 5) TUTORIAL MODEL + ROUTES
// ====================

const tutorialSchema = new mongoose.Schema({
  name: String,
  icon: String,         // e.g. icon path or URL
  description: String,
  tutorialLink: String
});


const User = mongoose.model('User', userSchema);
const Publication = mongoose.model('Publication', publicationSchema);
const Team = mongoose.model('Team', teamSchema);
const Address = mongoose.model('Address', addressSchema);
const Technology = mongoose.model('Technology', technologySchema);
const ResourceText = mongoose.model('ResourceText', resourceTextSchema);
const Role = mongoose.model('Role', roleSchema);
const Tutorial = mongoose.model('Tutorial', tutorialSchema);



// Middleware for authentication
const authenticate = async (req, res, next) => {
    let token = req.header('Authorization');
    if (!token) return res.status(401).send('Access denied');
    token = token.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded._id });
        if (!user) return res.status(403).send('No user found');
        req.user = user;
        next();
    } catch (err) {
        res.status(400).send('Invalid token');
    }
};

// Middleware to check team membership
const checkTeamMembership = async (req, res, next) => {
    try {
        const isMember = await Team.findOne({ userId: req.user._id });
        if (!isMember) return res.status(403).send('Access denied: Not a team member');
        next();
    } catch (err) {
        res.status(500).send(err.message);
    }
};

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// API Endpoints

// User registration
app.post('/api/users/register',[upload.single('image')], async (req, res) => {
    try {
        const { name, email, address, role, bio, timeline, password } = req.body;
        const image = req.file.path;

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            name,
            email,
            address,
            image,
            role,
            bio,
            timeline,
            password: hashedPassword,
        });

        await user.save();
        res.status(201).send('User registered successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// User authentication
app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Invalid email or password');

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid email or password');

        const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
        res.header('Authorization', token).send({user:user,token:token});
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Add team member
app.post('/api/team', authenticate, async (req, res) => {
    try {
        if (!req.user.isAdmin) return res.status(403).send('Access denied');

        const { userId } = req.body;
        const teamMember = new Team({
            userId,
            addedBy: req.user._id,
        });

        await teamMember.save();
        res.status(201).send('Team member added successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Remove team member
app.delete('/api/team/:userId', authenticate, async (req, res) => {
    try {
        if (!req.user.isAdmin) return res.status(403).send('Access denied');

        const { userId } = req.params;

        // Find and remove the team member
        const removedMember = await Team.findOneAndDelete({ userId });
        if (!removedMember) {
            return res.status(404).send('Team member not found');
        }

        res.status(200).send('Team member removed successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});


// Fetch all team members
app.get('/api/team', async (req, res) => {
    try {
        const teamMembers = await Team.find().exec();
        res.status(200).json(teamMembers);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Fetch all users 
app.get('/api/user', async (req, res) => {
    try {
        const users = await User.find().exec();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Add publication
app.post('/api/publications', [authenticate, checkTeamMembership, upload.single('coverImage')], async (req, res) => {
    try {
        const { title, authors, additionalAuthors, summary, doi } = req.body;
        const coverImage = req.file.path;

        const publication = new Publication({
            title,
            authors,
            additionalAuthors,
            summary,
            coverImage,
            doi,
        });

        await publication.save();
        res.status(201).send('Publication added successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Retrieve the 5 most recent publications
app.get('/api/publications', async (req, res) => {
    try {
        const publications = await Publication.find()
            .sort({ createdAt: -1 })  // Sort by creation date in descending order
            .limit(5)                 // Limit to 5 documents
            .exec();
        res.status(200).json(publications);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Retrieve all publications from a given year
app.get('/api/publications/year/:year', async (req, res) => {
    try {
        const year = parseInt(req.params.year, 10);
        const publications = await Publication.find({ year }).exec();
        res.status(200).json(publications);
    } catch (error) {
        res.status(500).send(error.message);
    }
});


// Retrieve a specific team member's details and their publications
app.get('/api/team/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const teamMember = await User.findById(userId).exec();
        if (!teamMember) return res.status(404).send('User not found');

        const publications = await Publication.find({ authors: userId }).exec();

        res.status(200).json({ teamMember, publications });
    } catch (error) {
        res.status(500).send(error.message);
    }
});


/**
 * POST /api/address
 *  Create a new address document. 
 *  Authentication required. Possibly admin-only if you want.
 */
app.post('/api/address', authenticate, async (req, res) => {
  try {
    const { room, department, institution, city, state, postalCode, country } = req.body;
    const address = new Address({
      room,
      department,
      institution,
      city,
      state,
      postalCode,
      country
    });
    await address.save();
    return res.status(201).json(address);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * GET /api/address
 *  Return all addresses or adapt for a single address if you only expect one doc.
 */
app.get('/api/address', async (req, res) => {
  try {
    const addresses = await Address.find().exec();
    return res.json(addresses);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * PATCH /api/address/:id
 *  Update a specific address doc by ID. Authentication required.
 */
app.patch('/api/address/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body; 
    const updated = await Address.findByIdAndUpdate(
      id,
      { $set: updates },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Address not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * POST /api/role
 *  Create a new role doc (e.g. "PhD Student")
 */
app.post('/api/role', authenticate, async (req, res) => {
  try {
    const { roleName } = req.body;
    const role = new Role({ roleName });
    await role.save();
    return res.status(201).json(role);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * GET /api/role
 *  Return all roles, or you can store only one doc if that's your use case.
 */
app.get('/api/role', async (req, res) => {
  try {
    const roles = await Role.find().exec();
    return res.json(roles);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * PATCH /api/role/:id
 *  Update role (like changing roleName).
 */
app.patch('/api/role/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const updated = await Role.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Role not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * POST /api/resourcetext
 */
app.post('/api/resourcetext', authenticate,async (req, res) => {
  try {
    const { text } = req.body;
    const resource = new ResourceText({ text });
    await resource.save();
    return res.status(201).json(resource);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * GET /api/resourcetext
 */
app.get('/api/resourcetext', async (req, res) => {
  try {
    const allResources = await ResourceText.find().exec();
    return res.json(allResources);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * PATCH /api/resourcetext/:id
 */
app.patch('/api/resourcetext/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body; // { text: "New resource text" }
    const updated = await ResourceText.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Resource text not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});


/**
 * POST /api/technology
 */
app.post('/api/technology', [authenticate, upload.single('icon')], async (req, res) => {
  try {
    const { name, description, downloadLink } = req.body;
    const icon = req.file.path;
    const tech = new Technology({ name, icon, description, downloadLink });
    await tech.save();
    return res.status(201).json(tech);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * GET /api/technology
 */
app.get('/api/technology', async (req, res) => {
  try {
    const techs = await Technology.find().exec();
    return res.json(techs);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * PATCH /api/technology/:id
 */
app.patch('/api/technology/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body; // partial updates
    const updated = await Technology.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Technology not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * POST /api/tutorial
 */
app.post('/api/tutorial', [authenticate, upload.single('newIcon')], async (req, res) => {
  try {
    const { name, description, tutorialLink } = req.body;
    const newIcon = req.file.path;
    const tut = new Tutorial({ name, newIcon, description, tutorialLink });
    await tut.save();
    return res.status(201).json(tut);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * GET /api/tutorial
 */
app.get('/api/tutorial', async (req, res) => {
  try {
    const tutorials = await Tutorial.find().exec();
    return res.json(tutorials);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

/**
 * PATCH /api/tutorial/:id
 */
app.patch('/api/tutorial/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const updated = await Tutorial.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Tutorial not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
