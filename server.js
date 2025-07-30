require('dotenv').config();

const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('./models/User');
const Transaction = require('./models/Transaction'); // Still needed for deposits/top-ups
const multer = require('multer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const fs = require('fs');
const cors = require('cors');

const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);
const cron = require('node-cron');

mongoose.connect(process.env.MONGODB_URI, {
})
.then(() => console.log('MongoDB Connected...'))
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        console.log('--- Passport LocalStrategy: Login Attempt ---');
        console.log('Login Email:', email);

        const user = await User.findOne({ email: email });
        if (!user) {
            console.log('User not found for email:', email);
            return done(null, false, { message: 'That email is not registered' });
        }

        console.log('User found:', user.email);

        const isMatch = await bcrypt.compare(password, user.password);
        console.log('bcrypt.compare result (isMatch):', isMatch);

        if (!isMatch) {
            console.log('Password comparison failed.');
            return done(null, false, { message: 'Password incorrect' });
        }
        if (!user.isVerified) {
            console.log('User email not verified:', user.email);
            return done(null, false, { message: 'Please verify your email address.' });
        }

        console.log('Login successful for user:', user.email);
        return done(null, user);
    } catch (err) {
        console.error('Passport LocalStrategy Error:', err);
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);

        const allowedOrigin = app.locals.baseUrl;

        if (origin === allowedOrigin || origin.startsWith(`http://localhost:${process.env.PORT || 2100}`)) {
            callback(null, true);
        } else {
            console.warn(`CORS: Blocking request from unauthorized origin: ${origin}. Expected: ${allowedOrigin}`);
            callback(new Error('Not allowed by CORS'), false);
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET || 'a_very_secret_key_for_development_only_change_this_in_production',
    resave: false,
    saveUninitialized: false,
    name: 'tradexa_session_id',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24
    }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.query = req.query;
    res.locals.app = {
        locals: {
            baseUrl: app.locals.baseUrl
        }
    };
    next();
});

const uploadDir = 'public/uploads/profile_pictures/';

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log(`Created upload directory: ${uploadDir}`);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        console.log(`Multer: Destination callback. Upload directory: ${uploadDir}`);
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const newFilename = file.fieldname + '-' + Date.now() + path.extname(file.originalname);
        console.log(`Multer: Filename callback. New filename: ${newFilename}`);
        cb(null, newFilename);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024
    },
    fileFilter: function (req, file, cb) {
        console.log('Multer fileFilter: Checking file type...');
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            console.log(`Multer fileFilter: File type OK - ${file.mimetype}`);
            return cb(null, true);
        } else {
            console.warn(`Multer fileFilter: Invalid file type - ${file.mimetype}`);
            cb(new Error('Only image files (JPG, JPEG, PNG, GIF) are allowed!'), false);
        }
    }
});

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Please log in to access this resource.' });
    }
    res.redirect('/login?error=Please log in to access this page.');
}

function isAdmin(req, res, next) {
    if (req.session.isAdmin === true) {
        return next();
    }
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
        return res.status(403).json({ success: false, message: 'Forbidden. You do not have admin privileges.' });
    }
    res.status(403).render('error', { message: 'Access Denied: You are not authorized to view this page.', title: 'Access Denied' });
}

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

transporter.verify(function (error, success) {
    if (error) {
        console.error("Nodemailer transporter verification failed:", error);
    } else {
        console.log("Nodemailer transporter is ready to send messages.");
    }
});

const investmentPlans = {
    Starter: {
        minDeposit: 500,
        maxDeposit: 10000,
        durationDays: 4,
        dailyROI: 0.20,
        withdrawalAfterDays: 4,
    },
    Growth: {
        minDeposit: 10000,
        maxDeposit: 25000,
        durationDays: 4,
        dailyROI: 0.40,
        withdrawalAfterDays: 4,
    },
    Elite: {
        minDeposit: 25000,
        maxDeposit: Infinity,
        durationDays: 4,
        dailyROI: 0.60,
        withdrawalAfterDays: 4,
    }
};

const cryptoWallets = {
    BTC: process.env.BTC_WALLET_ADDRESS || 'bc1qexamplebtcaddress',
    USDT_ERC20: process.env.USDT_ERC20_WALLET_ADDRESS || '0xexampleusdt_erc20address',
    USDT_TRC20: process.env.USDT_TRC20_WALLET_ADDRESS || 'Texampleusdt_trc20address',
    USDC: process.env.USDC_WALLET_ADDRESS || '0xexampleusdcaddress',
    ETH: process.env.ETH_WALLET_ADDRESS || '0xexampleethaddress'
};

const supportEmail = 'contact.tradexa@gmail.com';

const userSockets = new Map();

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('registerUser', (userId) => {
        if (userId) {
            if (!userSockets.has(userId)) {
                userSockets.set(userId, new Set());
            }
            userSockets.get(userId).add(socket.id);
            console.log(`User ${userId} registered socket ${socket.id}. Total sockets for user: ${userSockets.get(userId).size}`);
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        userSockets.forEach((sockets, userId) => {
            if (sockets.has(socket.id)) {
                sockets.delete(socket.id);
                if (sockets.size === 0) {
                    userSockets.delete(userId);
                }
                console.log(`Socket ${socket.id} removed for user ${userId}. Remaining user sockets: ${sockets.size}`);
                return;
            }
        });
    });
});

async function emitBalanceUpdate(userId) {
    try {
        const user = await User.findById(userId);
        if (user && userSockets.has(userId.toString())) {
            const sockets = userSockets.get(userId.toString());
            const balance = user.balance.toFixed(2);
            const currentPlan = user.currentPlan;
            const initialInvestment = user.initialInvestment.toFixed(2);

            let withdrawable = 0;
            if (user.currentPlan !== 'None' && user.planStartDate && user.planEndDate) {
                const planDetails = investmentPlans[user.currentPlan];
                if (planDetails) {
                    const now = new Date();
                    const planStartDate = new Date(user.planStartDate);
                    const planEndDate = new Date(user.planEndDate);

                    if (user.currentPlan === 'Starter' || user.currentPlan === 'Elite') {
                        const withdrawalAvailableDate = new Date(planStartDate.getTime() + planDetails.withdrawalAfterDays * 24 * 60 * 60 * 1000);
                        if (now >= withdrawalAvailableDate) {
                            withdrawable = user.balance.toFixed(2);
                        }
                    } else if (user.currentPlan === 'Growth') {
                        if (now >= planEndDate) {
                            withdrawable = user.balance.toFixed(2);
                        }
                    }
                }
            }

            sockets.forEach(socketId => {
                io.to(socketId).emit('balanceUpdate', {
                    balance: balance,
                    currentPlan: currentPlan,
                    initialInvestment: initialInvestment,
                    withdrawable: withdrawable
                });
                console.log(`Emitted balanceUpdate to socket ${socketId} for user ${userId}: Balance $${balance}`);
            });
        } else {
            console.log(`User ${userId} not found or no active sockets for balance update.`);
        }
    } catch (error) {
        console.error('Error emitting balance update:', error);
    }
}

async function calculateDailyProfits() {
    console.log('Running daily profit calculation...');
    try {
        const users = await User.find({
            currentPlan: { $ne: 'None' },
            planStartDate: { $ne: null }
        });

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        for (const user of users) {
            const planDetails = investmentPlans[user.currentPlan];

            if (!planDetails) {
                console.warn(`User ${user.email} has an unknown plan: ${user.currentPlan}. Skipping profit calculation.`);
                continue;
            }

            const daysSincePlanStart = Math.floor((today.getTime() - user.planStartDate.getTime()) / (1000 * 60 * 60 * 24));

            const lastUpdateDate = user.lastProfitUpdate ? new Date(user.lastProfitUpdate) : null;
            if (lastUpdateDate && lastUpdateDate.toDateString() === today.toDateString()) {
                console.log(`Profit for user ${user.email} already applied today. Skipping.`);
                continue;
            }

            const planDurationDays = planDetails.durationDays;
            if (daysSincePlanStart >= planDurationDays) {
                console.log(`Plan for user ${user.email} (${user.currentPlan}) has ended. Resetting plan.`);
                // Apply final profit for the last day of the plan
                const dailyProfit = user.initialInvestment * user.dailyROI;
                user.balance += dailyProfit;
                user.investments.push({ date: new Date(), value: user.balance });

                // Reset plan-specific fields, but keep the balance untouched.
                user.currentPlan = 'None';
                user.dailyROI = 0;
                user.initialInvestment = 0; // Reset initial investment for the *next* plan
                user.planStartDate = null;
                user.planEndDate = null;
                user.pendingStarterDeposit = 0; // Clear any pending starter deposits
                user.lastProfitUpdate = new Date(); // Mark profit as updated for today
                await user.save();
                console.log(`User ${user.email}'s plan reset after completion. Final balance (preserved): $${user.balance.toFixed(2)}`);
                await emitBalanceUpdate(user._id);
                continue;
            }

            const dailyProfit = user.initialInvestment * user.dailyROI;
            user.balance += dailyProfit;
            user.lastProfitUpdate = new Date();
            user.investments.push({ date: new Date(), value: user.balance });

            await user.save();
            console.log(`Applied daily profit of $${dailyProfit.toFixed(2)} for user ${user.email}. New balance: $${user.balance.toFixed(2)}`);
            await emitBalanceUpdate(user._id);
        }
        console.log('Daily profit calculation complete.');
    } catch (error) {
        console.error('Error during daily profit calculation:', error);
    }
}

cron.schedule('0 0 * * *', () => { // Runs daily at midnight
    console.log('Cron job: Initiating daily profit calculation...');
    calculateDailyProfits();
}, {
    scheduled: true,
    timezone: "Africa/Lagos"
});

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/login", (req, res) => {
    const messages = req.session.messages || [];
    req.session.messages = [];
    res.render('login', { error: messages[0], success: req.query.success || null });
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error('Passport authentication error:', err);
            return next(err);
        }
        if (!user) {
            req.session.messages = [info.message];
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('req.logIn error:', err);
                return next(err);
            }
            if (req.body.rememberMe) {
                req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 7;
                console.log('User session extended for 7 days (Remember Me)');
            } else {
                req.session.cookie.maxAge = 1000 * 60 * 60 * 24;
                console.log('User session set to default 24 hours');
            }
            console.log('User logged in successfully:', user.email);
            return res.redirect('/dashboard');
        });
    })(req, res, next);
});

app.get('/signup', (req, res) => {
    res.render('register', { error: null, success: null });
});

app.post('/signup', async (req, res) => {
    const { fullName, email, phoneNumber, gender, country, password, confirmPassword } = req.body;

    console.log('--- User Registration Attempt ---');
    if (!fullName || !email || !phoneNumber || !gender || !country || !password || !confirmPassword) {
        return res.render('register', { error: 'All fields are required.', success: null });
    }

    if (password !== confirmPassword) {
        return res.render('register', { error: 'Passwords do not match.', success: null });
    }
    if (password.length < 6) {
        return res.render('register', { error: 'Password must be at least 6 characters.', success: null });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            if (!existingUser.isVerified) {
                return res.render('register', { error: 'This email is already registered but not verified. Please check your inbox or try logging in.', success: null });
            }
            return res.render('register', { error: 'Email already registered. Please login or use a different email.', success: null });
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationTokenExpires = Date.now() + 3600000 * 24;

        const newUser = new User({
            fullName,
            email,
            phoneNumber,
            gender,
            country,
            password: password,
            isVerified: false,
            verificationToken,
            verificationTokenExpires,
            balance: 0,
            currentPlan: 'None',
            dailyROI: 0,
            initialInvestment: 0,
            investments: [],
            pendingStarterDeposit: 0,
            lastProfitUpdate: null,
            profilePicture: null
        });

        await newUser.save();

        const verificationUrl = `${res.locals.app.locals.baseUrl}/verify-email/${verificationToken}`;
        console.log(`--- VERIFICATION EMAIL URL BEING SENT: ${verificationUrl} ---`);

        const mailOptions = {
            from: `"Tradexa" <${supportEmail}>`,
            to: newUser.email,
            subject: 'Tradexa Account Verification',
            html: `
                <p>Hello ${newUser.fullName},</p>
                <p>Thank you for registering with Tradexa. Please verify your email address by clicking the link below:</p>
                <p><a href="${verificationUrl}">Verify Your Email</a></p>
                <p>This link will expire in 24 hours.</p>
                <p>If you did not register for a Tradexa account, please ignore this email.</p>
                <p>Best regards,<br>The Tradexa Team</p>
                <p><a href="mailto:${supportEmail}">${supportEmail}</a></p>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('Verification email sent to:', newUser.email);

        return res.redirect('/login?success=Registration successful! Please check your email to verify your account before logging in.');

    } catch (error) {
        console.error('Error during user registration:', error);

        let errorMessage = 'Registration failed. Please try again.';
        if (error.name === 'ValidationError') {
            errorMessage = Object.values(error.errors).map(err => err.message).join(', ');
        } else if (error.code === 11000) {
            errorMessage = 'This email is already registered. Please login or use a different email.';
        }

        return res.render('register', { error: errorMessage, success: null });
    }
});

app.get('/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;

        const user = await User.findOne({
            verificationToken: token,
            verificationTokenExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.redirect('/login?error=Email verification link is invalid or has expired. Please try registering again.');
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        console.log('User email verified successfully:', user.email);
        return res.redirect('/login?success=Your email has been successfully verified! You can now log in.');

    } catch (error) {
        console.error('Error during email verification:', error);
        return res.redirect('/login?error=An error occurred during email verification. Please try again.');
    }
});

app.get('/forgot-password', (req, res) => {
    const errorMessage = req.query.error || null;
    const successMessage = req.query.success || null;
    res.render('forgot-password', { error: errorMessage, success: successMessage });
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.render('forgot-password', { error: 'Please enter your email address.', success: null });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            console.log('Forgot password request for unregistered email:', email);
            return res.redirect('/forgot-password?success=If that email address is registered, you will receive a password reset link.');
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpires = Date.now() + 3600000;

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetTokenExpires;
        await user.save();

        const resetUrl = `${res.locals.app.locals.baseUrl}/reset-password/${resetToken}`;

        const mailOptions = {
            from: `"Tradexa" <${supportEmail}>`,
            to: user.email,
            subject: 'Tradexa Password Reset',
            html: `
                <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                <p>Please click on the following link, or paste this into your browser to complete the process:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
                <p>Best regards,<br>The Tradexa Team</p>
                <p><a href="mailto:${supportEmail}">${supportEmail}</a></p>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('Password reset email sent to:', user.email);

        return res.redirect('/forgot-password?success=If that email address is registered, you will receive a password reset link.');

    } catch (error) {
        console.error('Error during forgot password request:', error);
        return res.render('forgot-password', { error: 'An error occurred. Please try again.', success: null });
    }
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.redirect('/login?error=Password reset link is invalid or has expired. Please request a new one.');
        }

        res.render('reset-password', { token, error: null, success: null });
    } catch (error) {
        console.error('Error rendering reset password page:', error);
        return res.redirect('/login?error=An error occurred while trying to reset your password. Please try again.');
    }
});

app.post('/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { password, confirmPassword } = req.body;

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('reset-password', { token, error: 'Password reset link is invalid or has expired. Please request a new one.', success: null });
        }

        if (!password || !confirmPassword) {
            return res.render('reset-password', { token, error: 'Please enter and confirm your new password.', success: null });
        }

        if (password !== confirmPassword) {
            return res.render('reset-password', { token, error: 'Passwords do not match.', success: null });
        }

        if (password.length < 8) {
            return res.render('reset-password', { token, error: 'Password must be at least 8 characters long.', success: null });
        }

        user.password = password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        console.log('Password successfully reset for user:', user.email);
        return res.redirect('/login?success=Your password has been successfully reset. You can now log in with your new password.');

    } catch (error) {
        console.error('Error during password reset:', error);
        return res.render('reset-password', { token: req.params.token, error: 'An error occurred while resetting your password. Please try again.', success: null });
    }
});

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
            return next(err);
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destruction error during logout:', err);
                return next(err);
            }
            res.clearCookie('tradexa_session_id');
            res.redirect('/login?success=You have been logged out.');
        });
    });
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        const user = req.user;

        let withdrawableBalance = 0;
        if (user.currentPlan !== 'None' && user.planStartDate && user.planEndDate) {
            const planDetails = investmentPlans[user.currentPlan];

            if (planDetails) {
                const now = new Date();
                const planStartDate = new Date(user.planStartDate);
                const planEndDate = new Date(user.planEndDate);

                if (user.currentPlan === 'Starter' || user.currentPlan === 'Elite') {
                    const withdrawalAvailableDate = new Date(planStartDate.getTime() + planDetails.withdrawalAfterDays * 24 * 60 * 60 * 1000);
                    if (now >= withdrawalAvailableDate) {
                        withdrawableBalance = user.balance;
                    }
                } else if (user.currentPlan === 'Growth') {
                    if (now >= planEndDate) {
                        withdrawableBalance = user.balance;
                    }
                }
            }
        }

        const chartData = user.investments.map(inv => ({
            date: inv.date.toISOString().split('T')[0],
            value: inv.value
        }));

        res.render('dashboard', {
            title: 'Dashboard - Tradexa',
            user: user,
            withdrawableBalance: withdrawableBalance.toFixed(2),
            investments: chartData,
            currentPage: 'dashboard',
        });
    } catch (err) {
        console.error('Error rendering dashboard:', err);
        res.status(500).send('Server Error');
    }
});

app.get('/my-plans', isAuthenticated, async (req, res) => {
    try {
        const user = req.user;

        const errorMessage = req.query.error || null;

        let currentProjectedValue = user.initialInvestment;
        let daysPassed = 0;
        const planDetails = investmentPlans[user.currentPlan];

        if (user.currentPlan !== 'None' && user.planStartDate && planDetails) {
            const now = new Date();
            daysPassed = Math.floor((now - user.planStartDate) / (1000 * 60 * 60 * 24));

            if (daysPassed > 0) {
                const effectiveDays = Math.min(daysPassed, planDetails.durationDays);
                currentProjectedValue = user.initialInvestment;
                for (let i = 0; i < effectiveDays; i++) {
                    currentProjectedValue *= (1 + user.dailyROI);
                }
            }
        }
        currentProjectedValue = Math.max(currentProjectedValue, user.initialInvestment);

        const chartData = user.investments.map(inv => ({
            date: inv.date.toISOString().split('T')[0],
            value: inv.value
        }));

        res.render('myplans', {
            user: user,
            currentProjectedValue: currentProjectedValue.toFixed(2),
            chartData: JSON.stringify(chartData),
            planDetails: planDetails,
            plans: investmentPlans,
            error: errorMessage,
            title: 'My Plans',
            currentPage: 'my-plans'
        });

    } catch (error) {
        console.error('Error fetching user plans:', error);
        return res.redirect('/dashboard?error=Could not load your plans. Please try again.');
    }
});

app.post('/select-plan', isAuthenticated, async (req, res) => {
    const { planName } = req.body;
    const user = req.user;

    if (!planName || !investmentPlans[planName]) {
        return res.redirect('/my-plans?error=Invalid plan selected.');
    }

    // If user has an active plan and tries to select a different one, prevent it.
    // If they select the same plan, it's considered for top-up.
    if (user.currentPlan !== 'None' && user.currentPlan !== planName) {
        return res.redirect('/my-plans?error=You already have an active plan. Consider topping up your existing plan.');
    }

    req.session.selectedDepositPlan = planName;
    console.log(`User ${user.email} selected plan: ${planName} for deposit.`);

    res.redirect('/deposit?success=Plan selected! Now enter your deposit amount.');
});

app.get('/deposit', isAuthenticated, async (req, res) => {
    try {
        const user = req.user;

        const successMessage = req.query.success || null;
        const errorMessage = req.query.error || null;

        let selectedPlanName = req.session.selectedDepositPlan;
        let planDetails = null;
        let isTopUp = false;

        // If no plan is selected in session AND user has no active plan, redirect to select plan
        if (!selectedPlanName && user.currentPlan === 'None') {
            return res.redirect('/my-plans?error=Please select an investment plan before making a deposit.');
        }

        // If no plan selected in session, but user has an active plan, assume top-up for current plan
        if (!selectedPlanName && user.currentPlan !== 'None') {
            selectedPlanName = user.currentPlan;
            isTopUp = true;
            planDetails = investmentPlans[selectedPlanName];
            console.log(`User ${user.email} is requesting to top-up their active ${selectedPlanName} plan.`);
        } else if (selectedPlanName && investmentPlans[selectedPlanName]) {
            // If a plan is selected in session, use it
            planDetails = investmentPlans[selectedPlanName];
            if (user.currentPlan === selectedPlanName) {
                isTopUp = true; // It's a top-up if the selected plan is their current active plan
            }
            console.log(`User ${user.email} is selecting a new plan: ${selectedPlanName}.`);
        } else {
            // Fallback, should ideally be caught by the first check
            return res.redirect('/my-plans?error=Please select an investment plan before making a deposit.');
        }

        res.render('deposit', {
            title: 'Deposit Funds',
            currentPage: 'deposit',
            user: user,
            selectedPlan: selectedPlanName,
            planDetails: planDetails,
            isTopUp: isTopUp,
            error: errorMessage,
            success: successMessage
        });
    } catch (err) {
        console.error('Error rendering deposit page:', err);
        res.status(500).send('Server Error');
    }
});

app.post('/deposit', isAuthenticated, async (req, res) => {
    const { amount, paymentCurrency } = req.body;
    const depositAmount = parseFloat(amount);
    const user = req.user;

    if (isNaN(depositAmount) || depositAmount <= 0) {
        return res.redirect(`/deposit?error=Please enter a valid deposit amount.`);
    }

    let selectedPlanName = req.session.selectedDepositPlan;
    let planToProcess = null;
    let isNewActivation = false;

    // Determine the plan to process and if it's a new activation
    if (selectedPlanName && investmentPlans[selectedPlanName]) {
        planToProcess = investmentPlans[selectedPlanName];
        if (user.currentPlan === 'None' || user.currentPlan === selectedPlanName) {
            isNewActivation = true; // New activation or top-up of the same plan
        } else {
            // User has an active plan different from the one selected in session
            return res.redirect(`/my-plans?error=You already have an active ${user.currentPlan} plan. Please wait for it to complete or contact support to change plans.`);
        }
    } else if (user.currentPlan !== 'None') {
        // No plan selected in session, but user has an active plan (implies top-up)
        planToProcess = investmentPlans[user.currentPlan];
        selectedPlanName = user.currentPlan;
        isNewActivation = false; // It's a top-up, not a new activation
    } else {
        // No plan selected in session AND no active plan (user needs to choose)
        return res.redirect('/my-plans?error=No plan selected or invalid plan. Please choose a plan first.');
    }

    // Validation for deposit amount based on plan rules
    if (!isNewActivation && planToProcess.maxDeposit !== Infinity && (user.initialInvestment + depositAmount > planToProcess.maxDeposit)) {
        return res.redirect(`/deposit?error=Your total investment for the ${selectedPlanName} plan cannot exceed $${planToProcess.maxDeposit}. Please adjust your top-up amount.`);
    }
    if (isNewActivation && selectedPlanName !== 'Starter' && depositAmount < planToProcess.minDeposit) {
        return res.redirect(`/deposit?error=Minimum deposit for ${selectedPlanName} Plan is $${planToProcess.minDeposit}.`);
    }
    if (isNewActivation && selectedPlanName === 'Starter') {
        if (depositAmount + user.pendingStarterDeposit > planToProcess.maxDeposit) {
            return res.redirect(`/deposit?error=Your total Starter deposits cannot exceed $${planToProcess.maxDeposit}. Please adjust your amount.`);
        }
    }

    const supportedCurrencies = Object.keys(cryptoWallets);
    if (!paymentCurrency || !supportedCurrencies.includes(paymentCurrency)) {
        return res.redirect(`/deposit?error=Please select a valid payment currency.`);
    }

    try {
        let transactionType;
        if (isNewActivation && user.currentPlan === 'None') { // Truly new activation
            transactionType = 'Deposit';
        } else { // Top-up or new activation of same plan
            transactionType = 'Top-Up';
        }

        // Handle pending Starter deposits separately
        if (selectedPlanName === 'Starter' && transactionType === 'Deposit') {
            user.pendingStarterDeposit += depositAmount;
            await user.save();
        }

        const newTransaction = new Transaction({
            userId: user._id,
            amount: depositAmount,
            currency: paymentCurrency,
            type: transactionType,
            status: 'Pending', // Deposits/Top-ups still start as 'Pending'
            walletAddressUsed: cryptoWallets[paymentCurrency],
            planName: selectedPlanName
        });
        await newTransaction.save();
        console.log('New deposit/top-up transaction recorded with status "Pending":', newTransaction);

        delete req.session.selectedDepositPlan; // Clear session after use

        const walletAddressToDisplay = cryptoWallets[paymentCurrency];
        let currencyLabel;
        switch (paymentCurrency) {
            case 'BTC': currencyLabel = 'Bitcoin (BTC)'; break;
            case 'USDT_ERC20': currencyLabel = 'USDT (ERC20)'; break;
            case 'USDT_TRC20': currencyLabel = 'USDT (TRC20)'; break;
            case 'USDC': currencyLabel = 'USDC'; break;
            case 'ETH': currencyLabel = 'Ethereum (ETH)'; break;
            default: currencyLabel = paymentCurrency;
        }

        return res.redirect(`/payment-instructions?amount=${depositAmount}&currency=${currencyLabel}&address=${walletAddressToDisplay}&plan=${selectedPlanName}`);

    } catch (error) {
        console.error('Error during deposit/top-up:', error);
        let redirectError = 'An error occurred during deposit. Please try again.';
        if (selectedPlanName) {
            redirectError += `&selectedPlan=${selectedPlanName}`;
        }
        return res.redirect(`/deposit?error=${redirectError}`);
    }
});

app.get('/payment-instructions', isAuthenticated, (req, res) => {
    const { amount, currency, address, plan } = req.query;
    if (!amount || !currency || !address || !plan) {
        return res.redirect('/dashboard?error=Missing payment details.');
    }
    res.render('paymentinstructions', {
        amount,
        currency,
        address,
        plan,
        title: 'Payment Instructions',
        currentPage: 'deposit'
    });
});

app.get('/transactions', isAuthenticated, async (req, res) => {
    try {
        // Fetch only Deposit and Top-Up transactions for the user
        const userTransactions = await Transaction.find({ userId: req.user._id, type: { $in: ['Deposit', 'Top-Up'] } }).sort({ createdAt: -1 });

        res.render('transactions', {
            transactions: userTransactions,
            error: req.query.error || null,
            success: req.query.success || null,
            title: 'Transaction History',
            currentPage: 'transactions'
        });
    } catch (error) {
        console.error('Error fetching user transactions:', error);
        res.redirect('/dashboard?error=Could not load transaction history. Please try again.');
    }
});

app.get('/profile', isAuthenticated, async (req, res) => {
    try {
        const user = req.user;
        res.render('profile', {
            title: 'My Profile - Tradexa',
            user: user,
            currentPage: 'profile'
        });
    } catch (err) {
        console.error('Error rendering profile page:', err);
        res.status(500).send('Server Error');
    }
});

app.post('/profile/upload', isAuthenticated, (req, res, next) => {
    console.log('--- Profile Picture Upload Attempt ---');
    upload.single('profilePicture')(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            console.error('Multer Error during upload:', err.code, err.message);
            let userMessage = 'File upload failed.';
            if (err.code === 'LIMIT_FILE_SIZE') {
                userMessage = 'Image file is too large. Max 5MB allowed.';
            } else if (err.code === 'LIMIT_UNEXPECTED_FILE') {
                userMessage = 'Unexpected file field. Please ensure you are uploading a profile picture.';
            } else {
                userMessage = `File upload error: ${err.message}`;
            }
            return res.status(400).json({ success: false, message: userMessage });
        } else if (err) {
            if (err.message === 'Only image files (JPG, JPEG, PNG, GIF) are allowed!') {
                console.warn('File type error during upload:', err.message);
                return res.status(400).json({ success: false, message: err.message });
            }
            console.error('General Error during upload (Multer or custom fileFilter):', err.message);
            return res.status(500).json({ success: false, message: 'An unexpected error occurred during file upload.' });
        }

        try {
            if (!req.file) {
                console.warn('No file uploaded by Multer after successful processing (req.file is undefined).');
                return res.status(400).json({ success: false, message: 'No image file uploaded or file type not supported.' });
            }

            console.log('File received by Multer:', {
                originalname: req.file.originalname,
                mimetype: req.file.mimetype,
                size: req.file.size,
                filename: req.file.filename,
                path: req.file.path
            });

            const user = req.user;
            if (!user) {
                console.error('User not found in req.user after successful authentication. This is unexpected.');
                return res.status(404).json({ success: false, message: 'User session not found. Please log in again.' });
            }

            const publicFilePath = '/uploads/profile_pictures/' + req.file.filename;
            console.log('Attempting to save public file path to DB:', publicFilePath);

            if (user.profilePicture && user.profilePicture.startsWith('/uploads/profile_pictures/')) {
                const oldFilePath = path.join(__dirname, 'public', user.profilePicture);
                fs.unlink(oldFilePath, (unlinkErr) => {
                    if (unlinkErr) {
                        console.warn(`Failed to delete old profile picture ${oldFilePath}:`, unlinkErr.message);
                    } else {
                        console.log(`Successfully deleted old profile picture: ${oldFilePath}`);
                    }
                });
            }

            user.profilePicture = publicFilePath;
            await user.save();
            console.log('User profilePicture updated in DB successfully. New path:', user.profilePicture);

            res.status(200).json({
                success: true,
                message: 'Profile picture updated successfully!',
                profilePicture: publicFilePath
            });

        } catch (error) {
            console.error('Error during profile picture update (after Multer, during DB save or unlink):', error);
            res.status(500).json({ success: false, message: error.message || 'Failed to update profile picture. Please try again.' });
        }
    });
});

app.post('/profile/update', isAuthenticated, async (req, res) => {
    try {
        console.log('Profile update request received.');
        const user = req.user;
        console.log('Authenticated user for update:', user ? user.email : 'None');

        if (!user) {
            console.error('Error: User not found in req.user for profile update. Unauthorized access attempt.');
            return res.status(401).json({ success: false, message: 'Unauthorized. Please log in again.' });
        }

        const { fullName, phoneNumber, gender, country } = req.body;
        console.log('Received data for profile update:', { fullName, phoneNumber, gender, country });

        if (!fullName || !phoneNumber || !gender || !country) {
            console.warn('Validation failed for profile update: Missing required fields.');
            return res.status(400).json({ success: false, message: 'All fields (Full Name, Phone Number, Gender, Country) are required.' });
        }

        user.fullName = fullName;
        user.phoneNumber = phoneNumber;
        user.gender = gender;
        user.country = country;

        await user.save();
        console.log(`User ${user.email} profile details updated successfully in DB.`);

        req.login(user, (err) => {
            if (err) {
                console.error('Error re-logging in user after profile update:', err);
            } else {
                console.log(`User ${user.email} session refreshed after profile update.`);
            }
        });

        res.json({ success: true, message: 'Profile details updated successfully!', user: { fullName: user.fullName } });

    } catch (error) {
        console.error('Error updating user profile details:', error);
        if (error.name === 'ValidationError') {
            const validationErrors = Object.values(error.errors).map(err => err.message).join(', ');
            console.error('Mongoose Validation Error during profile update:', validationErrors);
            res.status(400).json({ success: false, message: `Validation error: ${validationErrors}` });
        } else {
            res.status(500).json({ success: false, message: 'Failed to update profile details. An unexpected server error occurred.' });
        }
    }
});

app.get('/withdraw', isAuthenticated, async (req, res) => {
    try {
        const user = req.user;

        const minWithdrawal = 50;
        let withdrawableBalance = 0;

        if (user.currentPlan !== 'None' && user.planStartDate && user.planEndDate) {
            const planDetails = investmentPlans[user.currentPlan];

            if (planDetails) {
                const now = new Date();
                const planStartDate = new Date(user.planStartDate);
                const planEndDate = new Date(user.planEndDate);

                if (user.currentPlan === 'Starter' || user.currentPlan === 'Elite') {
                    const withdrawalAvailableDate = new Date(planStartDate.getTime() + planDetails.withdrawalAfterDays * 24 * 60 * 60 * 1000);
                    if (now >= withdrawalAvailableDate) {
                        withdrawableBalance = user.balance;
                    }
                } else if (user.currentPlan === 'Growth') {
                    if (now >= planEndDate) {
                        withdrawableBalance = user.balance;
                    }
                }
            }
        }

        res.render('withdraw', {
            title: 'Withdraw Funds',
            currentPage: 'withdraw',
            user: user,
            withdrawableBalance: withdrawableBalance.toFixed(2),
            minWithdrawal: minWithdrawal.toFixed(2),
            cryptoWallets: cryptoWallets,
            supportEmail: supportEmail,
            error: req.query.error || null,
            success: req.query.success || null
        });
    } catch (error) {
        console.error('Error rendering withdraw page:', error);
        res.redirect('/dashboard?error=Could not load withdraw page. Please try again.');
    }
});

app.post('/withdraw', isAuthenticated, async (req, res) => {
    const { amount, currency, walletAddress } = req.body;
    const withdrawalAmount = parseFloat(amount);
    const user = req.user;

    // --- IMPORTANT: All withdrawal requests are now purely frontend-driven.
    // --- The backend will only validate and respond, but NOT record or modify balance.

    if (isNaN(withdrawalAmount) || withdrawalAmount <= 0) {
        return res.status(400).json({ success: false, message: 'Please enter a valid withdrawal amount.' });
    }
    const minWithdrawal = 50;
    if (withdrawalAmount < minWithdrawal) {
        return res.status(400).json({ success: false, message: `Minimum withdrawal amount is $${minWithdrawal.toFixed(2)}.` });
    }
    if (withdrawalAmount > user.balance) {
        return res.status(400).json({ success: false, message: 'Insufficient balance.' });
    }
    if (!currency || !cryptoWallets[currency]) {
        return res.status(400).json({ success: false, message: 'Please select a valid cryptocurrency.' });
    }
    if (!walletAddress || walletAddress.trim() === '') {
        return res.status(400).json({ success: false, message: `Please enter your ${currency} wallet address.` });
    }

    let isWithdrawalAllowed = false;
    if (user.currentPlan !== 'None' && user.planStartDate && user.planEndDate) {
        const planDetails = investmentPlans[user.currentPlan];

        if (planDetails) {
            const now = new Date();
            const planStartDate = new Date(user.planStartDate);
            const planEndDate = new Date(user.planEndDate);

            if (user.currentPlan === 'Starter' || user.currentPlan === 'Elite') {
                const withdrawalAvailableDate = new Date(planStartDate.getTime() + planDetails.withdrawalAfterDays * 24 * 60 * 60 * 1000);
                if (now >= withdrawalAvailableDate) {
                    isWithdrawalAllowed = true;
                }
            } else if (user.currentPlan === 'Growth') {
                if (now >= planEndDate) {
                    isWithdrawalAllowed = true;
                }
            }
        }
    }

    if (!isWithdrawalAllowed) {
        return res.status(400).json({ success: false, message: 'Withdrawal is not yet available for your current plan or plan has not matured.' });
    }

    try {
        // IMPORTANT CHANGES:
        // 1. Balance is NOT modified.
        // 2. No Transaction record is created for withdrawals.
        // 3. No email is sent from the backend for withdrawal requests.

        console.log(`User ${user.email} attempted withdrawal of $${withdrawalAmount} ${currency} to ${walletAddress}. Request passed validation.`);
        // The frontend will display the success message from here.
        res.status(200).json({ success: true, message: 'Withdrawal request submitted successfully!' });

    } catch (err) {
        console.error('Withdrawal error (server-side unexpected error):', err);
        // This error message will be displayed to the user if a server-side error occurs
        res.status(500).json({ success: false, message: 'Failed to process withdrawal. Please try again.' });
    }
});

app.get('/admin/login', (req, res) => {
    const messages = req.session.messages || [];
    req.session.messages = [];
    res.render('admin_login', { error: messages[0], success: req.query.success || null, title: 'Admin Login' });
});

app.post('/admin/login', (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        req.session.messages = ['Please enter both email and password.'];
        return res.redirect('/admin/login');
    }

    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

    if (email !== adminEmail) {
        req.session.messages = ['Invalid admin credentials.'];
        return res.redirect('/admin/login');
    }

    bcrypt.compare(password, adminPasswordHash)
        .then(isMatch => {
            if (!isMatch) {
                req.session.messages = ['Invalid admin credentials.'];
                return res.redirect('/admin/login');
            }

            req.session.isAdmin = true;
            req.session.isLoggedIn = true;
            console.log('Admin logged in successfully:', email);
            return res.redirect('/admin/dashboard');
        })
        .catch(err => {
            console.error('Error during admin login bcrypt compare:', err);
            req.session.messages = ['An error occurred during login.'];
            return res.redirect('/admin/login');
        });
});

app.get('/admin/dashboard', isAdmin, async (req, res) => {
    try {
        // Admin dashboard will now ONLY fetch Deposit and Top-Up transactions with status 'Pending'.
        const pendingTransactions = await Transaction.find({ type: { $in: ['Deposit', 'Top-Up'] }, status: 'Pending' }).populate('userId', 'fullName email').sort({ createdAt: -1 });

        res.render('admin_dashboard', {
            title: 'Admin Dashboard',
            pendingTransactions: pendingTransactions,
            query: req.query,
            error: null,
            currentPage: 'admin-dashboard'
        });
    } catch (error) {
        console.error('Error fetching pending transactions for admin dashboard:', error);
        res.render('admin_dashboard', {
            title: 'Admin Dashboard',
            pendingTransactions: [],
            error: 'Could not load pending transactions. Please try again.',
            query: req.query,
            currentPage: 'admin-dashboard'
        });
    }
});

app.post('/admin/transaction-action', isAdmin, async (req, res) => {
    const { transactionId, action } = req.body;

    if (!transactionId || !action || !['confirm', 'reject'].includes(action)) {
        return res.redirect('/admin/dashboard?error=Invalid transaction ID or action.');
    }

    try {
        const transaction = await Transaction.findById(transactionId);

        if (!transaction) {
            return res.redirect('/admin/dashboard?error=Transaction not found.');
        }

        // IMPORTANT: Ensure this logic ONLY applies to Deposit/Top-Up transactions.
        if (transaction.type === 'Withdrawal') {
            console.warn(`Admin attempted to process a withdrawal transaction (${transactionId}). Withdrawals are no longer tracked in the database or affect user balance.`);
            return res.redirect('/admin/dashboard?error=Withdrawal transactions are not processed through this panel.');
        }

        if (transaction.status !== 'Pending') {
            return res.redirect(`/admin/dashboard?error=Transaction is already ${transaction.status}.`);
        }

        if (action === 'confirm') {
            transaction.status = 'Confirmed';
            transaction.confirmedAt = new Date();

            const user = await User.findById(transaction.userId);
            if (user) {
                // This logic is ONLY for Deposit and Top-Up transactions
                user.balance += transaction.amount;

                if (transaction.type === 'Deposit' && transaction.planName === 'Starter') {
                    const starterMinActivation = investmentPlans.Starter.minDeposit;
                    user.pendingStarterDeposit = user.pendingStarterDeposit || 0;

                    if (user.pendingStarterDeposit >= starterMinActivation && user.currentPlan === 'None') {
                        user.currentPlan = 'Starter';
                        user.initialInvestment = user.pendingStarterDeposit;
                        user.dailyROI = investmentPlans.Starter.dailyROI;
                        user.planStartDate = new Date();
                        user.planEndDate = new Date(user.planStartDate);
                        user.planEndDate.setDate(user.planEndDate.getDate() + investmentPlans.Starter.durationDays);
                        user.investments.push({ date: new Date(), value: user.balance });
                        user.pendingStarterDeposit = 0;

                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        yesterday.setHours(0, 0, 0, 0);
                        user.lastProfitUpdate = yesterday;

                        console.log(`User ${user.email} activated Starter plan with $${user.initialInvestment} (accumulated and confirmed).`);
                    } else if (user.currentPlan === 'Starter' && user.pendingStarterDeposit < starterMinActivation) {
                        console.log(`Confirmed $${transaction.amount} for Starter accumulation. User ${user.email} total pending: $${user.pendingStarterDeposit}.`);
                    } else if (user.currentPlan === 'Starter' && user.pendingStarterDeposit >= starterMinActivation && user.initialInvestment === 0) {
                        user.currentPlan = 'Starter';
                        user.initialInvestment = user.pendingStarterDeposit;
                        user.dailyROI = investmentPlans.Starter.dailyROI;
                        user.planStartDate = new Date();
                        user.planEndDate = new Date(user.planStartDate);
                        user.planEndDate.setDate(user.planEndDate.getDate() + investmentPlans.Starter.durationDays);
                        user.investments.push({ date: new Date(), value: user.balance });
                        user.pendingStarterDeposit = 0;
                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        yesterday.setHours(0, 0, 0, 0);
                        user.lastProfitUpdate = yesterday;
                        console.log(`User ${user.email} activated Starter plan with $${user.initialInvestment} (multiple deposits confirmed).`);
                    }


                } else if (transaction.type === 'Deposit') {
                    user.currentPlan = transaction.planName;
                    user.initialInvestment = transaction.amount;
                    user.dailyROI = investmentPlans[transaction.planName].dailyROI;
                    user.planStartDate = new Date();
                    user.planEndDate = new Date(user.planStartDate);
                    user.planEndDate.setDate(user.planEndDate.getDate() + investmentPlans[transaction.planName].durationDays);
                    user.investments.push({ date: new Date(), value: user.balance });

                    const yesterday = new Date();
                    yesterday.setDate(yesterday.getDate() - 1);
                    yesterday.setHours(0, 0, 0, 0);
                    user.lastProfitUpdate = yesterday;

                    console.log(`User ${user.email} activated ${transaction.planName} plan with $${user.initialInvestment} (confirmed).`);
                } else if (transaction.type === 'Top-Up') {
                    user.initialInvestment += transaction.amount;
                    user.investments.push({ date: new Date(), value: user.balance });
                    console.log(`User ${user.email} topped up their ${transaction.planName} plan with $${transaction.amount}. New confirmed initial investment: $${user.initialInvestment}.`);
                }
                console.log(`User ${user.email} balance updated to $${user.balance.toFixed(2)} after deposit/top-up confirmation.`);

                await user.save();
                await emitBalanceUpdate(user._id);

                const mailOptions = {
                    from: `"Tradexa" <${supportEmail}>`,
                    to: user.email,
                    subject: `Tradexa: Transaction Confirmed!`,
                    html: `
                        <p>Hello ${user.fullName},</p>
                        <p>Your transaction of <strong>$${transaction.amount.toFixed(2)} ${transaction.currency}</strong> (${transaction.type}) has been successfully confirmed by our team.</p>
                        <p>Your account balance has been updated to <strong>$${user.balance.toFixed(2)}</strong>.</p>
                        <p>You can view your updated balance and transaction history by logging into your dashboard:</p>
                        <p><a href="${res.locals.app.locals.baseUrl}/dashboard">Go to Your Dashboard</a></p>
                        <p>Thank you for choosing Tradexa!</p>
                        <p>Best regards,<br>The Tradexa Team</p>
                        <p><a href="mailto:${supportEmail}">${supportEmail}</a></p>
                    `
                };

                try {
                    await transporter.sendMail(mailOptions);
                    console.log(`Transaction confirmation email sent to: ${user.email} for transaction ${transaction._id}`);
                } catch (emailError) {
                    console.error(`Failed to send transaction confirmation email to ${user.email}:`, emailError);
                }

            } else {
                console.warn(`User not found for transaction ${transaction._id}. Balance not updated and email not sent.`);
            }
            await transaction.save(); // Save transaction status
            return res.redirect('/admin/dashboard?success=Transaction confirmed successfully!');

        } else if (action === 'reject') {
            transaction.status = 'Rejected';
            transaction.confirmedAt = new Date();
            await transaction.save();

            if (transaction.type === 'Deposit' && transaction.planName === 'Starter') {
                const user = await User.findById(transaction.userId);
                if (user && user.pendingStarterDeposit >= transaction.amount) {
                    user.pendingStarterDeposit -= transaction.amount;
                    await user.save();
                    console.log(`Rejected Starter deposit. User ${user.email} pendingStarterDeposit reduced by $${transaction.amount}.`);
                }
            }
            console.log(`Transaction ${transaction._id} rejected.`);
            return res.redirect('/admin/dashboard?success=Transaction rejected.');
        }

    } catch (error) {
        console.error('Error processing admin transaction action:', error);
        return res.redirect('/admin/dashboard?error=An error occurred while processing the transaction.');
    }
});

app.get('/admin/reset-plan/:email', isAdmin, async (req, res) => {
    const { email } = req.params;
    try {
        const user = await User.findOneAndUpdate(
            { email: email },
            {
                currentPlan: 'None',
                planStartDate: null,
                planEndDate: null,
                dailyROI: 0,
                initialInvestment: 0,
                // IMPORTANT: As per user request, if admin resets plan, balance should be reset too.
                // This specific admin function is for a full user account reset.
                balance: 0,
                profilePicture: '',
                lastProfitUpdate: null
            },
            { new: true }
        );

        if (user) {
            console.log(`Admin: User ${email}'s plan, balance, and profile picture have been reset.`);
            await emitBalanceUpdate(user._id);
            res.send(`User ${email}'s plan, balance, and profile picture have been reset. You can now try depositing again.`);
        } else {
            res.status(404).send(`User with email ${email} not found.`);
        }
    } catch (error) {
        console.error('Error resetting user plan:', error);
        res.status(500).send('An error occurred while resetting the user plan.');
    }
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying admin session:', err);
            return res.redirect('/admin/login?error=Error logging out.');
        }
        res.clearCookie('tradexa_session_id');
        res.redirect('/admin/login?success=You have been logged out from admin panel.');
    });
});

const PORT = process.env.PORT || 2100;

async function startServer() {
    try {
        // In a hosted environment, the hosting platform will provide the public URL.
        // Render uses RENDER_EXTERNAL_URL, Railway uses RAILWAY_STATIC_URL, etc.
        // You should set BASE_URL in your hosting environment variables if your platform doesn't provide a standard one.
        const publicUrl = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || process.env.RAILWAY_STATIC_URL || `http://localhost:${PORT}`;

        app.locals.baseUrl = publicUrl;
        console.log(`App Base URL set to: ${app.locals.baseUrl}`);

        server.listen(PORT, () => {
            console.log(`Express and Socket.IO server listening on port ${PORT}`);
            console.log(`Access Tradexa at ${publicUrl}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        app.listen(PORT, () => {
            console.log(`Express server listening on port ${PORT} (server.listen failed)`);
            console.log(`Access Tradexa at http://localhost:${PORT}`);
        });
    }
}

startServer();
