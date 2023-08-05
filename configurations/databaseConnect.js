const mongoose = require('mongoose'); // Importing mongoose

// Function for establishing the mongodb database connection
const database = async () => {
    try{
        await mongoose.connect(process.env.DATABASE_URL)
        .then(result => {
            console.log("DB connection established.");
        })
        .catch(err => {
            console.log(err.message);
        })

    }catch(error){
        console.log(error.message);
    }
}

module.exports = database;
