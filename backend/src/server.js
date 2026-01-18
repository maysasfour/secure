const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

// Security Middleware
app.use(helmet()); // Sets various HTTP headers for security
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
    res.json({ message: "Secure Campus API is running..." });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));