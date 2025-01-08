//////////////////////////////
//  server.js (or index.js)
//////////////////////////////

// 1. Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const dotenv = require('dotenv');
const cors = require('cors');
// NEW: Import Vercel Blob method
const { put } = require('@vercel/blob');

dotenv.config();

const app = express();

// 2. Allow requests from specific origin
app.use(cors({
    origin: '*', // Frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
}));

app.use(express.json());

// 3. Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
});

// 4. Define Schemas & Models

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    address: { type: String },
    role: { type: String, required: true },
    bio: { type: String },
    image: { type: String },
    education: [{
        institution: String,
        degree: String,
        startDate: Date,
        endDate: Date,
    }],
    experience: [{
        institution: String,
        degree: String,
        startDate: Date,
        endDate: Date,
    }],
    links: [{
        linkType: String,
        link: String,
    }],
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
});

const publicationSchema = new mongoose.Schema({
    title: { type: String, required: true },
    authors: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
    additionalAuthors: [{ type: String }], 
    summary: { type: String },
    coverImage: { type: String },
    doi: { type: String },
    year: { type: Number, default: () => new Date().getFullYear() },
}, { timestamps: true });

const teamSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isAlumni: { type: Boolean, default: false }
});

// ADDRESS
const addressSchema = new mongoose.Schema({
  room: String,
  department: String,
  institution: String,
  city: String,
  state: String,
  postalCode: String,
  country: String
});

// ROLE
const roleSchema = new mongoose.Schema({
  roleName: String // e.g. "PhD Student"
});

// ABOUT
const aboutSchema = new mongoose.Schema({
  text: String // Could be a large string 
});

// TECHNOLOGY
const technologySchema = new mongoose.Schema({
  name: String,
  icon: String,         // e.g. URL to icon
  description: String,
  downloadLink: String  
});

// TUTORIAL
const tutorialSchema = new mongoose.Schema({
  name: String,
  newIcon: String,      
  description: String,
  tutorialLink: String
});

// Create models
const User = mongoose.model('User', userSchema);
const Publication = mongoose.model('Publication', publicationSchema);
const Team = mongoose.model('Team', teamSchema);
const Address = mongoose.model('Address', addressSchema);
const Role = mongoose.model('Role', roleSchema);
const AboutText = mongoose.model('AboutText', aboutSchema);
const Technology = mongoose.model('Technology', technologySchema);
const Tutorial = mongoose.model('Tutorial', tutorialSchema);

// 5. Middleware for authentication
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

// 6. Configure Multer to use Memory Storage
const storage = multer.memoryStorage();
const upload = multer({ storage });

///////////////////////////////////////////////////////
//                    API ROUTES
///////////////////////////////////////////////////////

// ===================
// USER REGISTRATION
// ===================
app.post('/api/users/register', upload.single('image'), async (req, res) => {
  try {
    // Extract main fields
    const { name, email, address, role, bio, password } = req.body;

    // Parse nested JSON fields if they exist
    const education = JSON.parse(req.body.education || '[]');
    const experience = JSON.parse(req.body.experience || '[]');
    const links = JSON.parse(req.body.links || '[]');

    // If file was uploaded, upload to Vercel Blob
    let uploadedImageUrl = null;
    if (req.file) {
      const fileBuffer = req.file.buffer;
      const originalName = req.file.originalname;
      // Upload to Vercel Blob
      const { url } = await put(`user-images/${Date.now()}-${originalName}`, fileBuffer, {
        access: 'public',
        contentType: req.file.mimetype
      });
      uploadedImageUrl = url;
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create & save user
    const user = new User({
      name,
      email,
      address,
      role,
      bio,
      image: uploadedImageUrl, // store the Vercel Blob URL
      education,
      experience,
      links,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).send('User registered successfully');
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).send('Internal Server Error: ' + error.message);
  }
});

// ===================
// USER LOGIN
// ===================
app.post('/api/users/login', async (req, res) => {
  try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) return res.status(400).send('Invalid email or password');

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).send('Invalid email or password');

      const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
      res.header('Authorization', token).send({ user, token });
  } catch (error) {
      res.status(500).send(error.message);
  }
});

// ===================
// TEAM MANAGEMENT
// ===================
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

app.delete('/api/team/:userId', authenticate, async (req, res) => {
    try {
        if (!req.user.isAdmin) return res.status(403).send('Access denied');
        const { userId } = req.params;

        const removedMember = await Team.findOneAndDelete({ userId });
        if (!removedMember) {
            return res.status(404).send('Team member not found');
        }
        res.status(200).send('Team member removed successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Toggle Alumni
app.patch('/api/team/:userId/alumni', authenticate, async (req, res) => {
    try {
        if (!req.user.isAdmin) return res.status(403).send('Access denied');

        const { userId } = req.params;
        const member = await Team.findOne({ userId });
        if (!member) return res.status(404).send('Team member not found');

        member.isAlumni = !member.isAlumni; // Toggle
        await member.save();

        res.status(200).send({
            message: 'Team member alumni status toggled successfully',
            updatedMember: member
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/team', async (req, res) => {
    try {
        const teamMembers = await Team.find().exec();
        res.status(200).json(teamMembers);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// ===================
// USERS
// ===================
app.get('/api/user', async (req, res) => {
    try {
        const users = await User.find().exec();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/admins', async (req, res) => {
    try {
        const admins = await User.find({ isAdmin: true }).exec();
        if (admins.length === 0) {
            return res.status(404).json({ message: 'No admins found' });
        }
        res.status(200).json(admins);
    } catch (error) {
        res.status(500).json({ 
          message: 'An error occurred while fetching admins', 
          error: error.message 
        });
    }
});

app.get('/api/user/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).exec();
        if (!user) return res.status(404).send('User not found');
        res.status(200).json(user);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// ===================
// PUBLICATIONS
// ===================
app.post('/api/publications', [authenticate, checkTeamMembership, upload.single('coverImage')], async (req, res) => {
    try {
        const { title, authors, additionalAuthors, summary, doi } = req.body;

        let coverImageUrl = null;
        if (req.file) {
          const buffer = req.file.buffer;
          const originalName = req.file.originalname;
          const { url } = await put(`cover-images/${Date.now()}-${originalName}`, buffer, {
            access: 'public',
            contentType: req.file.mimetype
          });
          coverImageUrl = url;
        }

        const publication = new Publication({
            title,
            authors,
            additionalAuthors,
            summary,
            coverImage: coverImageUrl,
            doi,
        });

        await publication.save();
        res.status(201).send('Publication added successfully');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/publications', async (req, res) => {
    try {
        const publications = await Publication.find()
            .sort({ createdAt: -1 })
            .limit(5)
            .exec();
        res.status(200).json(publications);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/publications/year/:year', async (req, res) => {
    try {
        const year = parseInt(req.params.year, 10);
        const publications = await Publication.find({ year }).exec();
        res.status(200).json(publications);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Retrieve specific member & their publications
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

// ===================
// ADDRESS
// ===================
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

app.get('/api/address', async (req, res) => {
  try {
    const addresses = await Address.find().exec();
    return res.json(addresses);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.patch('/api/address/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body; 
    const updated = await Address.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Address not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// ===================
// ROLE
// ===================
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

app.get('/api/role', async (req, res) => {
  try {
    const roles = await Role.find().exec();
    return res.json(roles);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

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

// ===================
// ABOUT TEXT
// ===================
app.post('/api/about', authenticate, async (req, res) => {
  try {
    const { text } = req.body;
    const resource = new AboutText({ text });
    await resource.save();
    return res.status(201).json(resource);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get('/api/about', async (req, res) => {
  try {
    const allResources = await AboutText.find().exec();
    return res.json(allResources);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.patch('/api/about/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const updated = await AboutText.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Resource text not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// ===================
// TECHNOLOGY
// ===================
app.post('/api/technology', [authenticate, upload.single('icon')], async (req, res) => {
  try {
    const { name, description, downloadLink } = req.body;

    let iconUrl = null;
    if (req.file) {
      const buffer = req.file.buffer;
      const originalName = req.file.originalname;
      const { url } = await put(`tech-icons/${Date.now()}-${originalName}`, buffer, {
        access: 'public',
        contentType: req.file.mimetype
      });
      iconUrl = url;
    }

    const tech = new Technology({ 
      name, 
      icon: iconUrl, 
      description, 
      downloadLink 
    });
    await tech.save();
    return res.status(201).json(tech);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get('/api/technology', async (req, res) => {
  try {
    const techs = await Technology.find().exec();
    return res.json(techs);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.patch('/api/technology/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const updated = await Technology.findByIdAndUpdate(id, { $set: updates }, { new: true });
    if (!updated) return res.status(404).json({ message: 'Technology not found' });
    return res.json(updated);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// ===================
// TUTORIAL
// ===================
app.post('/api/tutorial', [authenticate, upload.single('newIcon')], async (req, res) => {
  try {
    const { name, description, tutorialLink } = req.body;

    let newIconUrl = null;
    if (req.file) {
      const buffer = req.file.buffer;
      const originalName = req.file.originalname;
      const { url } = await put(`tutorial-icons/${Date.now()}-${originalName}`, buffer, {
        access: 'public',
        contentType: req.file.mimetype
      });
      newIconUrl = url;
    }

    const tut = new Tutorial({ 
      name, 
      newIcon: newIconUrl, 
      description, 
      tutorialLink 
    });
    await tut.save();
    return res.status(201).json(tut);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get('/api/tutorial', async (req, res) => {
  try {
    const tutorials = await Tutorial.find().exec();
    return res.json(tutorials);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

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

// ===================
// START SERVER
// ===================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
