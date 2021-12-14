const express = require('express');
const router = express.Router();
const User = require('../models/user.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

router.post('/register',async (req, res) => {
      const { firstname,lastname, email, password } = req.body;
  
      try {
        // see if user exists
        let user = await User.findOne({ email });
        if (user) {
          return res
            .status(400)
            .json({ errors: [{ msg: 'User already exists' }] });
        }
        // get users gravatar
        user = new User({firstname,lastname, email, password});
        //encrypt password
  
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();
  
        //return jsonwebtoken
  
        const payload = {
          user: {
            id: user.id,
          },
        };
        jwt.sign(
          payload,
          config.get('jwtToken'),
          { expiresIn: 360000 },
          (err, token) => {
            if (err) throw err;
            res.json({ user, token });
          }
        );
      } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
      }
    }
  );
  router.post('/login', async (req, res) => {
    const login = await User.findOne({ email: req.body.email });
    if (login != null) {
        const validPassword = await bcrypt.compare(req.body.password, login.password);
        if (validPassword) {
            const tokenData = {
                firstname: login.firstname,
                lastname: login.lastname,
                email: login.email,
            }
            const payload = {
                user: {
                  id: login.id,
                },
              };
            const createdToken = 
            jwt.sign(
                payload,
                config.get('jwtToken'),
                { expiresIn: 360000 },
                (err, token) => {
                  if (err) throw err;
                  res.json({ user, token });
                }
              );
            res.status(200).json({ message: 'Logged in successfully', token: createdToken, User})
        } else {
            res.status(400).json({ message: 'Please verify your E-mail or Password' });
        }
    } else {
        res.status(400).json({ message: 'Please verify your E-mail or Password' });
    }
});
  module.exports = router;