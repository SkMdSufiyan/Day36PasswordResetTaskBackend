const express = require('express'); // Importing express package
const dotenv = require('dotenv'); // Importing dotenv package
dotenv.config();

// Importing the function "database" which establishes connection with the mongodb DB
const database = require('./configurations/databaseConnect.js');
const cors = require('cors'); // Importing cross origin resource sharing
const authRoutes = require('./routes/auth.routes.js'); // Importing the routes which performs signup, login, logout, reset password operations

const app = express(); // Creating express app

database(); // Executing the database connection function

app.use(cors()); // Using cors
app.use(express.json()); // Using "express.json()" for parsing the incoming req body into JSON payload

// Route for welcome message
app.get('/', (req, res) => {
    res.status(200).send("Welcome to the users (signup, login, reset password) application.");
});

// Adding middleware
app.use('/api', authRoutes);

// Starting the server
const PORT = process.env.PORT;
app.listen(PORT, () => {
    console.log(`The server is running on the PORT ${PORT}.`);
})
