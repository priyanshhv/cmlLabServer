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
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
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
    summary: { type: String },
    coverImage: { type: String },
    doi: { type: String },
});

const teamSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const User = mongoose.model('User', userSchema);
const Publication = mongoose.model('Publication', publicationSchema);
const Team = mongoose.model('Team', teamSchema);

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
        const { title, authors, summary, doi } = req.body;
        const coverImage = req.file.path;

        const publication = new Publication({
            title,
            authors,
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

// Retrieve publications
app.get('/api/publications', async (req, res) => {
    try {
        const publications = await Publication.find().exec();
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

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
