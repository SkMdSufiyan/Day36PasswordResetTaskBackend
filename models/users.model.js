const mongoose = require('mongoose'); // Importing mongoose

// Creating schema for user
const userSchema = new mongoose.Schema({
    name : {
        type : String,
        required : true,
        trim : true
    },
    email : {
        type : String,
        required : true,
        unique : true,
        trim : true
    },
    hashedPassword : {
        type : String,
        required : true,
        trim : true
    },
    city : {
        type : String,
        trim : true,
        default : "Not given"
    },
    country : {
        type : String,
        trim : true,
        default : "Not given"
    },
    resetPasswordToken : {
        type : String,
        trim : true,
        default : ""
    }
});

// Creating and exporting users model
module.exports = mongoose.model("users", userSchema);