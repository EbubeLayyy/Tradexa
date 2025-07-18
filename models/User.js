const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: [/.+@.+\..+/, 'Please enter a valid email address']
    },
    phoneNumber: {
        type: String,
        required: true,
        trim: true
    },
    gender: {
        type: String,
        required: true,
        enum: ['Male', 'Female', 'Other', 'Prefer not to say']
    },
    country: {
        type: String,
        required: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationTokenExpires: Date,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    balance: {
        type: Number,
        default: 0
    },
    currentPlan: {
        type: String,
        default: 'None'
    },
    dailyROI: {
        type: Number,
        default: 0
    },
    initialInvestment: {
        type: Number,
        default: 0
    },
    planStartDate: {
        type: Date,
        default: null
    },
    planEndDate: {
        type: Date,
        default: null
    },
    investments: [
        {
            date: { type: Date, default: Date.now },
            value: { type: Number, default: 0 }
        }
    ],
    pendingStarterDeposit: {
        type: Number,
        default: 0
    },
    profilePicture: {
        type: String,
        default: ''
    },
    lastProfitUpdate: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

userSchema.pre('save', async function(next) {
    if (this.isModified('password') || this.isNew) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;
