const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');


// creating the User schema:
const userSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    fullname: {
        type: String,
        default: ''
    },

    address: {
        type: String,
        default: ''
    },

    city: {
        type: String,
        default: ''
    },

    country: {
        type: String,
        default: ''
    }
});



// before saving the model, encrypt the password:
userSchema.pre("save", async function (next) {
    try {
        if (!this.isModified("password")) {
            return next();
        }

        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);

        next();
    } catch (err) {
        next(err);
    }
});

// method for comparing the hashed password and provided password :
userSchema.methods.comparePasswords = function (candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password)
        .then(isMatch => callback(null, isMatch))
        .catch(err => callback(err));
};

// create the User model
const User = mongoose.model('user', userSchema);


module.exports = User;