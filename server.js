require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Email Configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Models
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    role: { type: String, enum: ['Team Leader', 'Engineer'], required: true },
    password: { type: String, required: true },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    resetToken: String,
    resetTokenExpiry: Date,
    createdAt: { type: Date, default: Date.now }
});

const TeamMemberSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    fullName: { type: String, required: true },
    phoneNumber: { type: String, required: true }
});

const ReportSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    siteName: { type: String, required: true },
    boxCount: { type: Number, required: true },
    images: [{ type: String }], // Cloudinary URLs
    description: { type: String, required: true },
    dateTime: { type: Date, default: Date.now },
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    location: {
        latitude: Number,
        longitude: Number
    }
});

const User = mongoose.model('User', UserSchema);
const TeamMember = mongoose.model('TeamMember', TeamMemberSchema);
const Report = mongoose.model('Report', ReportSchema);

// Authentication Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.SESSION_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            throw new Error();
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// Admin Middleware
const verifyAdmin = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.SESSION_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user || user.role !== 'Team Leader') {
            return res.status(403).json({ message: 'Access denied. Team Leader only.' });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Please authenticate as admin' });
    }
};

// Routes

// Registration
app.post('/api/register', async (req, res) => {
    try {
        const { email, fullName, phoneNumber, role, password } = req.body;
        
        // Check if email exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            fullName,
            phoneNumber,
            role,
            password: hashedPassword
        });

        await user.save();
        res.status(201).json({ message: 'Registration successful' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.SESSION_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { email: user.email, fullName: user.fullName, role: user.role, phoneNumber: user.phoneNumber } });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get Profile
app.get('/api/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            email: user.email,
            fullName: user.fullName,
            phoneNumber: user.phoneNumber,
            role: user.role
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Forgot Password
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const resetToken = jwt.sign({ userId: user._id }, process.env.SESSION_SECRET, { expiresIn: '1h' });
        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
        
        await transporter.sendMail({
            to: email,
            subject: 'Password Reset Request',
            html: `
                <div style="background-color: #f5f5f5; padding: 20px;">
                    <h2>Password Reset Request</h2>
                    <p>Click the link below to reset your password:</p>
                    <a href="${resetLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                        Reset Password
                    </a>
                    <p>This link will expire in 1 hour.</p>
                </div>
            `
        });

        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send reset email' });
    }
});

// Reset Password
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        res.status(500).json({ error: 'Password reset failed' });
    }
});

// Update Profile
app.put('/api/profile', auth, async (req, res) => {
    try {
        const updates = req.body;
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        Object.keys(updates).forEach(key => {
            if (key !== 'password') {
                user[key] = updates[key];
            }
        });

        await user.save();
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Team Member Management
app.post('/api/team-members', auth, async (req, res) => {
    try {
        const { fullName, phoneNumber } = req.body;
        const teamMember = new TeamMember({
            userId: req.user._id,
            fullName,
            phoneNumber
        });
        await teamMember.save();
        res.status(201).json(teamMember);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add team member' });
    }
});

app.get('/api/team-members', auth, async (req, res) => {
    try {
        const teamMembers = await TeamMember.find({ userId: req.user._id });
        res.json(teamMembers);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch team members' });
    }
});

app.put('/api/team-members/:id', auth, async (req, res) => {
    try {
        const { fullName, phoneNumber } = req.body;
        const teamMember = await TeamMember.findOneAndUpdate(
            { _id: req.params.id, userId: req.user._id },
            { fullName, phoneNumber },
            { new: true }
        );
        if (!teamMember) {
            return res.status(404).json({ error: 'Team member not found' });
        }
        res.json(teamMember);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update team member' });
    }
});

app.delete('/api/team-members/:id', auth, async (req, res) => {
    try {
        const teamMember = await TeamMember.findOneAndDelete({
            _id: req.params.id,
            userId: req.user._id
        });
        if (!teamMember) {
            return res.status(404).json({ error: 'Team member not found' });
        }
        res.json({ message: 'Team member deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete team member' });
    }
});

// Report Management
app.post('/api/reports', auth, async (req, res) => {
    try {
        const { siteName, boxCount, images, description, location } = req.body;
        
        // Upload images to Cloudinary
        const uploadPromises = images.map(image => 
            cloudinary.uploader.upload(image, {
                folder: 'reports',
                resource_type: 'auto'
            })
        );
        
        const uploadResults = await Promise.all(uploadPromises);
        const imageUrls = uploadResults.map(result => result.secure_url);

        const report = new Report({
            userId: req.user._id,
            siteName,
            boxCount,
            images: imageUrls,
            description,
            location
        });

        await report.save();
        res.status(201).json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create report' });
    }
});

app.get('/api/reports', auth, async (req, res) => {
    try {
        const reports = await Report.find({ userId: req.user._id });
        res.json(reports);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// Get single report with images
app.get('/api/reports/:id', auth, async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user._id });
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }
        res.json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch report' });
    }
});

// Add more photos to existing report
app.post('/api/reports/:id/photos', auth, async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        // Check if report is pending
        if (report.status !== 'Pending') {
            return res.status(403).json({ error: 'Photos can only be added to pending reports' });
        }

        // Upload new images to Cloudinary
        const uploadPromises = req.body.images.map(image =>
            cloudinary.uploader.upload(image, {
                folder: 'reports',
                resource_type: 'auto'
            })
        );
        
        const uploadResults = await Promise.all(uploadPromises);
        const newImageUrls = uploadResults.map(result => result.secure_url);

        // Add new images to existing ones
        report.images = [...report.images, ...newImageUrls];
        await report.save();

        res.json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add photos' });
    }
});

// Delete photo from report
app.delete('/api/reports/:id/photos', auth, async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        if (report.status !== 'Pending') {
            return res.status(403).json({ error: 'Photos can only be deleted from pending reports' });
        }

        const { imageUrl } = req.body;
        const publicId = imageUrl.split('/').pop().split('.')[0];
        
        // Delete from Cloudinary
        await cloudinary.uploader.destroy(`reports/${publicId}`);
        
        // Remove from report
        report.images = report.images.filter(url => url !== imageUrl);
        await report.save();

        res.json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete photo' });
    }
});

app.put('/api/reports/:id', auth, async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        if (report.status !== 'Pending' && report.status !== 'Rejected') {
            return res.status(400).json({ error: 'Cannot update approved report' });
        }

        const { siteName, boxCount, description, newImages } = req.body;

        if (newImages && newImages.length > 0) {
            // Upload new images
            const uploadPromises = newImages.map(image =>
                cloudinary.uploader.upload(image, {
                    folder: 'reports',
                    resource_type: 'auto'
                })
            );
            const uploadResults = await Promise.all(uploadPromises);
            const newImageUrls = uploadResults.map(result => result.secure_url);
            report.images = [...report.images, ...newImageUrls];
        }

        report.siteName = siteName;
        report.boxCount = boxCount;
        report.description = description;

        await report.save();
        res.json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update report' });
    }
});

app.delete('/api/reports/:id', auth, async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        if (report.status !== 'Pending' && report.status !== 'Rejected') {
            return res.status(400).json({ error: 'Cannot delete approved report' });
        }

        // Delete images from Cloudinary
        const deletePromises = report.images.map(imageUrl => {
            const publicId = imageUrl.split('/').pop().split('.')[0];
            return cloudinary.uploader.destroy(`reports/${publicId}`);
        });
        await Promise.all(deletePromises);

        await Report.findByIdAndDelete(report._id);
        res.json({ message: 'Report deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete report' });
    }
});

// Admin Routes
app.get('/api/admin/reports', verifyAdmin, async (req, res) => {
    try {
        const reports = await Report.find().populate('userId', 'fullName email');
        res.json(reports);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// Delete report and all associated data
app.delete('/api/admin/reports/:id', verifyAdmin, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // Find the report
        const report = await Report.findById(req.params.id).session(session);
        if (!report) {
            await session.abortTransaction();
            return res.status(404).json({ message: 'Report not found' });
        }

        // Delete images from Cloudinary
        const deletePromises = report.images.map(async (imageUrl) => {
            try {
                const publicId = imageUrl.split('/').pop().split('.')[0];
                return await cloudinary.uploader.destroy(publicId);
            } catch (error) {
                console.error('Error deleting image from Cloudinary:', error);
            }
        });

        // Wait for all Cloudinary deletions to complete
        await Promise.all(deletePromises);

        // Delete the report from database
        await Report.findByIdAndDelete(req.params.id).session(session);

        // Commit the transaction
        await session.commitTransaction();
        res.json({ message: 'Report deleted successfully' });

    } catch (error) {
        // If anything fails, abort the transaction
        await session.abortTransaction();
        console.error('Error deleting report:', error);
        res.status(500).json({ message: 'Failed to delete report', error: error.message });
    } finally {
        session.endSession();
    }
});

app.put('/api/admin/reports/:id', async (req, res) => {
    try {
        const { status } = req.body;
        const report = await Report.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        ).populate('userId', 'email');

        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        // Send email notification
        await transporter.sendMail({
            to: report.userId.email,
            subject: `Report ${status}`,
            html: `
                <div style="background-color: ${status === 'Approved' ? '#d4edda' : '#f8d7da'}; padding: 20px;">
                    <h2>Report Status Update</h2>
                    <p>Your report for site "${report.siteName}" has been ${status.toLowerCase()}.</p>
                    <p>Date: ${report.dateTime.toLocaleDateString()}</p>
                </div>
            `
        });

        res.json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update report status' });
    }
});

// Serve static files
// User Management Routes
app.get('/api/users', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const total = await User.countDocuments();
        const users = await User.find()
            .select('email fullName role status createdAt')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        res.json({
            users,
            total,
            page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        const { email, fullName, role, status } = req.body;
        
        // Check if email exists and is not the same user
        const existingUser = await User.findOne({ email, _id: { $ne: req.params.id } });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const user = await User.findByIdAndUpdate(
            req.params.id,
            { email, fullName, role, status },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete related records
        await TeamMember.deleteMany({ userId: req.params.id });
        await Report.deleteMany({ userId: req.params.id });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Delete photo from report
app.delete('/api/reports/:id/photos', auth, async (req, res) => {
    try {
        const report = await Report.findOne({ _id: req.params.id, userId: req.user._id });
        
        if (!report) {
            return res.status(404).json({ error: 'Report not found' });
        }

        if (report.status !== 'Pending') {
            return res.status(403).json({ error: 'Photos can only be deleted from pending reports' });
        }

        const { imageUrl } = req.body;
        const publicId = imageUrl.split('/').pop().split('.')[0];
        
        // Delete from Cloudinary
        await cloudinary.uploader.destroy(`reports/${publicId}`);
        
        // Remove from report
        report.images = report.images.filter(url => url !== imageUrl);
        await report.save();

        res.json(report);
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete photo' });
    }
});

// Default route
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
