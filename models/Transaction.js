const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 0.01
    },
    currency: {
        type: String,
        required: true,
        enum: ['BTC', 'USDT_ERC20', 'USDT_TRC20', 'USDC', 'ETH']
    },
    type: {
        type: String,
        required: true,
        enum: ['Deposit', 'Top-Up', 'Withdrawal']
    },
    status: {
        type: String,
        required: true,
        enum: ['Pending', 'Confirmed', 'Rejected'],
        default: 'Pending'
    },
    transactionHash: {
        type: String,
        trim: true,
        sparse: true
    },
    walletAddressUsed: {
        type: String,
        required: true,
        trim: true
    },
    planName: {
        type: String,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    confirmedAt: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction;
