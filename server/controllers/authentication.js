const jwt = require('jwt-simple');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const {secret} = require('../config');


// create token for given user:
function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jwt.encode({sub: user.id, timestamp}, secret);
};


// signing in route callback
exports.signin = function(req, res, next) {
    res.send({token: tokenForUser(req.user), username: req.user.username, info: {
        fullname: req.user.fullname,
        address: req.user.address,
        city: req.user.city,
        country: req.user.country
    }});
}



// route callback for signing up:
exports.signup = async function(req, res, next) {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(422).send({
                error: "Username, email and password are required!"
            });
        }

        const usernameExists = await User.findOne({ username });

        if (usernameExists) {
            return res.status(422).send({
                error: "Username is already in use!"
            });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(422).send({
                error: "Email is already in use!"
            });
        }

        const user = new User({
            username,
            email,
            password
        });

        await user.save();

        res.json({
            token: tokenForUser(user),
            username: user.username
        });

    } catch (err) {
        next(err);
    }
};

exports.changePassword = async function (req, res, next) {
    try {
        const { currentPassword, newPassword } = req.body;

        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).send({ error: "User not found" });
        }

        user.comparePasswords(currentPassword, async (err, isMatch) => {
            if (err) {
                return next(err);
            }

            if (!isMatch) {
                return res.status(422).send({
                    error: "Current password is incorrect!"
                });
            }

            // Just assign the new password
            user.password = newPassword;

            // pre('save') hook will hash it automatically
            await user.save();

            res.json({
                message: "Password changed successfully!"
            });
        });

    } catch (err) {
        next(err);
    }
};

exports.editInfo = function(req, res, next) {
    const {fullname, address, city, country} = req.body;

    User.findByIdAndUpdate(req.user._id, {fullname, address, city, country}, {new: true})
        .then((user) => {
            res.send({info: {
                fullname: user.fullname,
                address: user.address,
                city: user.city,
                country: user.country
            }})
        })
}