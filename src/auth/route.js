const express = require('express');
const base64 = require('base-64');
const { User } = require('./model');
const jwt = require("jsonwebtoken");


const secret = process.env.SECRET

const authRoutes = express();

// Make a POST request to the/signup route with username and password.
authRoutes.post('/signup', signup);


async function signup(req, res, next) {
    try {
        // On a successful account creation, return a 201 status.
        const { username, password } = req.body;
        await User.createWithHashed(username, password);
        res.send(201);
    } catch (error) {
        // On any error, trigger your error handler with an appropriate error.
        next(new Error('Failed to create user'));
    }
}

// Send a basic authentication header with a properly encoded username and password combination.
// On a successful account login, return a 200 status with the user object in the body.
// On any error, trigger your error handler with the message “Invalid Login”.
async function signin(req, res, next) {
    let authorization = req.header('Authorization');
    if (!authorization.startsWith('Basic ')) {
        next(new Error('Invalid authorization scheme'));
        return;
    }

    authorization = base64.decode(authorization.replace('Basic ', ''));

    const [username, password] = authorization.split(':');
    let user = await User.findLoggedIn(username, password);
    if (user) {
        const payload = { username: user.username }
        const token = jwt.sign(payload, secret, { expiresIn: '10m' })
        res.send(token)
    } else {
        next(new Error('Invalid login'));
    }
}


async function validateToken(req, next) {
    const authorization = req.header("Authorization") ?? "";
    if (!authorization.startsWith('Bearer ')) {
        next(new Error("Missing Bearer Header"));
        return;
    }

    try {
        const token = authorization.replace("Bearer ", "")
        const decode = jwt.verify(token, secret);
        req.username = decode.username;
        next();
    }
    catch (error) {
        next(new Error("not authorized decode failed", { error: error }))

    }
}
module.exports = { authRoutes, validateToken, signin, signup, };