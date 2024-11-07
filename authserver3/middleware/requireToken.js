const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const Parent = mongoose.model('Parent');
const { jwtKey } = require('../config');

module.exports = (req, res, next) => {
    const { authorization } = req.headers;

    // Check if Authorization header exists
    if (!authorization) {
        return res.status(401).send({ error: "You must be logged in" });
    }

    // Extract token from Authorization header
    const token = authorization.replace("Bearer ", "");

    // Verify the token with the secret key
    jwt.verify(token, jwtKey, async (err, payload) => {
        if (err) {
            // Handle invalid token or expired token
            return res.status(401).send({ error: "Invalid or expired token, you must log in again" });
        }

        // Extract userId from the payload
        const { userId } = payload;

        try {
            // Find the parent user using the userId from the payload
            const newParent = await Parent.findById(userId);
            if (!newParent) {
                // Return error if the user is not found
                return res.status(404).send({ error: "User not found" });
            }

            // Attach the user object to the request for further use
            req.user = newParent;

            // Proceed to the next middleware or route handler
            next();
        } catch (err) {
            // Handle unexpected errors
            return res.status(500).send({ error: "Error while fetching user data" });
        }
    });
};
