// server.js - with debugging
const express = require('express');
const axios = require('axios');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const cors = require('cors');
require('dotenv').config();

console.log('Server process started.'); // DEBUG: Check if the script runs

// --- API Key Check ---
const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
    console.error('FATAL ERROR: GEMINI_API_KEY environment variable not found.');
    process.exit(1); // Stop the server if the key is missing
}
console.log('GEMINI_API_KEY loaded.'); // DEBUG: Confirm the key was found

const app = express();
const PORT = process.env.PORT || 3000;
const genAI = new GoogleGenerativeAI(apiKey); // Use the checked key

app.use(cors());
app.use(express.json());

app.post('/analyze', async (req, res) => {
    // ... (the rest of your /analyze route code remains the same)
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        console.log(`Fetching HTML from: ${url}`);
        const response = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const liveHtml = response.data;

        console.log('Analyzing HTML with Gemini...');
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-preview-05-20" });

        const healthPrompt = `Analyze the following HTML for health (performance, accessibility, SEO). Provide a score (0-100) and 3-5 markdown recommendations. Output valid JSON: {"score": <number>, "recommendations": "<markdown>"}. HTML: \`\`\`html\n${liveHtml}\n\`\`\``;
        const redesignPrompt = `Redesign the following HTML using only Tailwind CSS classes. Make it responsive. Replace alerts with console.log. Do not change text content. Output valid JSON: {"newHtml": "<html>..."}. HTML: \`\`\`html\n${liveHtml}\n\`\`\``;
        
        const [healthResult, redesignResult] = await Promise.all([
            model.generateContent(healthPrompt),
            model.generateContent(redesignPrompt)
        ]);

        const healthData = JSON.parse(healthResult.response.text());
        const redesignData = JSON.parse(redesignResult.response.text());
        
        console.log('Analysis complete.');
        res.json({ health: healthData, redesign: redesignData });

    } catch (error) {
        console.error('Error:', error.message);
        res.status(500).json({ error: 'Failed to analyze the website. The URL may be inaccessible or the server failed.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is now successfully listening on port ${PORT}`); // DEBUG: Confirm server is live
});