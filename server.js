// server.js - FINAL CORRECTED VERSION
const express = require('express');
const axios = require('axios');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.use(cors());
app.use(express.json());

// --- FIX: Function to clean the AI's JSON response ---
function sanitizeJsonResponse(rawText) {
    // Remove the markdown code block wrapper
    const cleanedText = rawText.replace(/^```json\s*|```$/g, '');
    return cleanedText;
}

app.post('/analyze', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        console.log(`Fetching HTML from: ${url}`);
        const response = await axios.get(url, { 
            headers: { 'User-Agent': 'Mozilla/5.0' },
            timeout: 10000 // Add a 10-second timeout
        });
        const liveHtml = response.data;

        console.log('Analyzing HTML with Gemini...');
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash-preview-05-20" });

        const healthPrompt = `Analyze the following HTML for health (performance, accessibility, SEO). Provide a score (0-100) and 3-5 markdown recommendations. Output valid JSON: {"score": <number>, "recommendations": "<markdown>"}. HTML: \`\`\`html\n${liveHtml}\n\`\`\``;
        const redesignPrompt = `Redesign the following HTML using only Tailwind CSS classes. Make it responsive. Replace alerts with console.log. Do not change text content. Output valid JSON: {"newHtml": "<html>..."}. HTML: \`\`\`html\n${liveHtml}\n\`\`\``;
        
        const [healthResult, redesignResult] = await Promise.all([
            model.generateContent(healthPrompt),
            model.generateContent(redesignPrompt)
        ]);

        // --- FIX: Sanitize the responses before parsing ---
        const healthData = JSON.parse(sanitizeJsonResponse(healthResult.response.text()));
        const redesignData = JSON.parse(sanitizeJsonResponse(redesignResult.response.text()));
        
        console.log('Analysis complete.');
        res.json({ health: healthData, redesign: redesignData });

    } catch (error) {
        console.error('Error:', error.message);
        if (error.code === 'ETIMEDOUT') {
            return res.status(504).json({ error: 'Failed to fetch the website. The server timed out.' });
        }
        res.status(500).json({ error: 'Failed to analyze the website. The server encountered an error.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is now successfully listening on port ${PORT}`);
});