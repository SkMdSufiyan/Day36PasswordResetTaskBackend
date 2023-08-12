const usersModel = require('../models/users.model.js'); // Importing the users model
const bcrypt = require('bcrypt'); // Importing bcrypt package
const jwt = require('jsonwebtoken'); // Importing the jsonwebtoken package
const nodemailer = require('nodemailer'); // Importing the nodemailer package


// Exporting the function which performs signup
exports.signup = async (req, res) => {
    try{
        const payload = req.body;
        // Loading all existing users' data
        const allExistingUsers = await usersModel.find();
        // Taking all users email ids
        const allExistingUsersEmailIds = allExistingUsers.map(val => val.email);

        // Checking whether a user already exists in the database with the supplied email id
        // isEmailAlreadyExists = 0 if there is no existing user with the supplied email in the database, otherwise isEmailAlreadyExists > 0
        const isEmailAlreadyExists = allExistingUsersEmailIds.filter(val => val === payload.email).length;

        if(isEmailAlreadyExists){
            // If an user already exists with this email id in the database returning message
            return res.status(400).send({message: "Email id already exists."})
        }

        // If there is no existing user with this email id in the database, then creating a new user
        // Hashing the password given by the user
        const hashValue = await bcrypt.hash(payload.password, 10);
        payload.hashedPassword = hashValue; // Storing it in the payload
        delete payload.password; // Deleting the password supplied by the user
        // Creating a new user
        const newUser = new usersModel(payload);
        newUser.save()
                .then(result => {
                    res.status(200).send({message: "User registered successfully.", _id: result._id});
                })
                .catch(err => {
                    res.status(400).send({message: "Failed to register the user.", error: err});
                })

    }catch(error){
        res.status(500).send({message: "Internal server error.", error: error});
    }

}


// Exporting the function which performs login
exports.login = async (req, res) => {
    try{
        const payload = req.body;
        // Checking whether the user exists in the database or not
        const existingUser = await usersModel.findOne({email: payload.email});
        if(existingUser){
            // If the user exists
            // Checking whether the password is correct or not
            const isValidCredentials = await bcrypt.compare(payload.password, existingUser.hashedPassword);

            if(isValidCredentials){
                // If the email and password are correct
                // Creating a jwt token
                const accessToken = jwt.sign({_id : existingUser._id}, process.env.SECRET_KEY_FOR_LOGIN);
                // Sending the jwt token into the cookies
                res.cookie("accessToken", accessToken, {expire : new Date() + 43200000}); 

                // Sending the user profile
                const userProfile = {...existingUser.toObject()};
                delete userProfile.hashedPassword;

                res.status(200).send({message: "Signed in successfully.", _id: existingUser._id, accessToken : accessToken, userProfile : userProfile});
            
            }else{
                // If the password is wrong, returning message
                res.status(400).send({message: "Invalid credentials."})
            }
        }else{
            // If the user does not exist in the database, returning message
            res.status(400).send({message: "User does not exist."});
        }

    }catch(error){
        res.status(500).send({message: "Internal server error.", error: err});
    }

}


// Exporting the function which performs logout
exports.logout = async (req, res) => {
    try{
        // Clearing the "accessToken" (which was stored after login) from the cookies
        await res.clearCookie("accessToken");
        res.status(200).send({message: "Signed out successfully."});
    }catch(error){
        res.status(500).send({message: "Internal server error.", error: error});
    }
}


// Exporting the function which performs forgot password
// It will send a link for resetting the password
exports.forgotPasswordSendEmail = async (req, res) => {
    try{

        const payload = req.body;
        const email = payload.email;
        // Checking whether the user exists in the database
        const userExists = await usersModel.findOne({email : email});
        
        if(userExists){
            // If the user exists in the database
            // Creating a reset password token
            const resetPasswordToken = jwt.sign({email : userExists.email }, process.env.SECRET_KEY_FOR_RESET_PASSWORD, {expiresIn : "15m"});

            // Storing the resetPasswordToken in the "resetPasswordToken" field of the user in the database
            await usersModel.findOneAndUpdate({email : email}, {$set: {resetPasswordToken : resetPasswordToken}});
    
            // Creating a reset password link with the frontend url followed by the "/reset-password/" route in frontend followed by the resetPasswordToken as params
            const resetPasswordLink = `${process.env.FRONTEND_URL}/reset-password/${resetPasswordToken}`;
    
            // Creating a nodemailer transporter
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.SENDER_EMAIL,
                    pass: process.env.SENDER_EMAIL_PASSWORD
                },
            });
    
            // Creating an email message
            const mailOptions = {
                from: process.env.SENDER_EMAIL,
                to: email,
                subject: 'Password Reset',
                html : `
                 <h2>Click the link below to reset your password:</h2>\n\n 
                 <a href=${resetPasswordLink}> ${resetPasswordLink} </a>
                 `
            };
      
            // Sending the email
            await transporter.sendMail(mailOptions)
            .then(result => {
                res.status(200).send({message : "Email has been sent successfully."});
            })
            .catch(err => {
                res.status(400).send({message: "Failed to send email.", error: err});
            })
        }else{
            res.status(400).send({message: "Email does not exist in the database."});
        }
       
    }catch(error){
        res.status(500).send({message: "Internal server error.", error: error});
    }
}


// Exporting the function which verifies the resetPasswordToken
// This function will be called from the frontend when the user opens the reset link
exports.verifyResetAccessToken = async (req, res) => {
    try{
        const resetToken = req.params.resetToken; // Taking the token from the params
        // Verifying the validity of the token
        jwt.verify(resetToken, process.env.SECRET_KEY_FOR_RESET_PASSWORD, (err, decodedToken) => {
            if(err){
                // If the token is invalid or expired, returning a message
                res.status(401).send({message: "Link is invalid / expired"});
            }else{
                const userData = await usersModel.findOne({email: decodedToken.email});
                if(userData.resetPasswordToken !== resetToken){
                    // If the user has already used the link and reset the password already
                    // Returning a message
                    return res.status(401).send({message: "Link is already used. Kindly initiate new request for resetting your password."});
                }
                // If the token is valid, returing a message and the user email decoded from the token
                res.status(200).send({message: "Token is verified and is valid. Can reset the password.", data: {email: decodedToken.email}});
            }
        })

    }catch(error){
        res.status(500).send({message: "Internal server error.", error : error});
    }
}


// Exporting the function which resets the password
// This function will be called from the frontend when the user opens the link and the token is verified and if the token is valid
exports.resetPassword = async (req, res) => {
    try{
        const resetToken = req.params.resetToken; // Taking the token from the params
        const {email, newPassword} = req.body; // Taking the email and newPassword from the request body

        // Verifying the validity of the token
        jwt.verify(resetToken, process.env.SECRET_KEY_FOR_RESET_PASSWORD, async (err, decodedToken) => {
            if(err){
                // If the token is invalid or expired, returning a message
                res.status(401).send({message: "Link is invalid / expired"});
            }else{
                // If the token is valid
                // Verifying whether the "resetPasswordToken" field of the user contains the same token or not (in the database)
                const userData = await usersModel.findOne({email: email});
                if(userData.resetPasswordToken === resetToken){
                    // If the "resetPasswordToken" field of the user contains the same token
                    // i.e. the user is using the reset link for the first time

                    // Then creating the hashed value of the new password
                    const hashedPassword = await bcrypt.hash(newPassword, 10);
                    // Updating the "hashedPassword" field of the user in the database
                    await usersModel.findOneAndUpdate({email : email}, {$set: {hashedPassword : hashedPassword, resetPasswordToken : "" }})
                    .then(result => {
                        res.status(200).send({message : "Password is updated successfully.", data : result});
                    })
                    .catch(err => {
                        res.status(400).send({message: "Failed to update the password.", error : err});
                    })
                }else{
                    // If the user has already used the link and reset the password already, or if the link is expired by that time
                    // Returning a message
                    res.status(401).send({message: "Link is either expired or already used. Kindly initiate new request for resetting your password."})
                }
            }
        });

    }catch(error){
        res.status(500).send({message: "Internal server error.", error: error})
    }

}











