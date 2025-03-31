const express = require("express");
const fs = require("fs");
const csvParser = require("csv-parser");
const path = require("path");

const app = express();
const PORT = 3000;
const csvFilePath = path.join(__dirname, "captured_traffic.csv");

// Serve frontend files
app.use(express.static(path.join(__dirname, "../public")));

// API to fetch attack logs (excluding "Normal" attack type)
app.get("/api/attacks", (req, res) => {
    const results = [];
    fs.createReadStream(csvFilePath)
        .pipe(csvParser())
        .on("data", (data) => {
            if (data.Attack_Type !== "Normal") {
                results.push(data);
            }
        })
        .on("end", () => res.json(results));
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log("📊 Visit http://localhost:3000 to view the dashboard");
});


