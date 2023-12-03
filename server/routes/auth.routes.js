const {Router} = require('express');
const User = require('../models/User');
const router = Router();
const config = require("config")

const bcrypt = require('bcryptjs');
const {check, validationResult} = require('express-validator');
// jwt Token
const jwt = require("jsonwebtoken")

// log up
router.post(
    '/registration',
    [
        check('email', 'Incorrect email').isEmail(),
        check('password', 'Password must be longer than 3 and shorter than 12').isLength({min: 3, max: 12}),
    ],
    async (req, res) => {
        try {
            console.log(req.body)
            const errors = validationResult(req); // Check the validationResult

            if (!errors.isEmpty()) {
                return res.status(400).json({message: 'Incorrect request', errors: errors.array()});
            }

            const {email, password} = req.body;

            const candidate = await User.findOne({email}); // получить пользователя

            if (candidate) {
                return res.status(400).json({message: `User with email ${email} already exists`});
            }

            const hashPassword = await bcrypt.hash(password, 8);
            const user = new User({email, password: hashPassword});

            await user.save();
            return res.json({message: 'User was created'});
        } catch (e) {
            console.error(e);
            res.status(500).send({message: 'Server error'});
        }
    }
);

// log in
router.post(
    '/login',

    async (req, res) => {
        try {

            const {email, password} = req.body

            const user = await User.findOne({email})
            if (!user) {
                return res.status(404).json({massage: "User not found"})
            }
            const isPassValid = bcrypt.compareSync(password, user.password)
            if (!isPassValid) {
                return res.status(400).json({massage: "Invalid password"})
            }

            const token = jwt.sign({id: user.id}, config.get("secretKey"), {expiresIn: "1h"})

            return res.json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    diskSpace: user.diskSpace,
                    usedSpace: user.usedSpace,
                    avatar: user.avatar
                }
            })

        } catch (e) {
            console.error(e);
            res.status(500).send({message: 'Server error'});
        }
    }
);

module.exports = router;
