const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Configuration ---
const NEON_DB_URL = 'postgresql://neondb_owner:npg_gvc3wdLM8PNH@ep-weathered-shape-anud7y6w-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';
const GOOGLE_SAFE_BROWSING_API_KEY = 'YOUR_GOOGLE_API_KEY'; // <-- Replace with your actual key
const OPENAI_API_KEY = 'sk-0b213b867acc4fd4bfcc02cb2b4604a8';

// --- Initialize clients ---
const pool = new Pool({ connectionString: NEON_DB_URL });
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// --- Database setup ---
async function initDB() {
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            verdict VARCHAR(20) NOT NULL,
            threat_type TEXT,
            ai_analysis TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_url ON scans(url);
    `;
    await pool.query(createTableQuery);
    console.log('✅ Database ready');
}
initDB().catch(console.error);

// --- Google Safe Browsing lookup ---
async function checkSafeBrowsing(url) {
    if (!GOOGLE_SAFE_BROWSING_API_KEY || GOOGLE_SAFE_BROWSING_API_KEY === 'YOUR_GOOGLE_API_KEY') {
        return { safe: true, threatType: null }; // fallback if key missing
    }
    try {
        const requestBody = {
            client: { clientId: "rusinan", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
            requestBody
        );
        if (response.data.matches && response.data.matches.length > 0) {
            const threat = response.data.matches[0].threatType;
            return { safe: false, threatType: threat };
        }
        return { safe: true, threatType: null };
    } catch (error) {
        console.error('Safe Browsing error:', error.message);
        return { safe: null, threatType: null }; // unknown
    }
}

// --- OpenAI analysis ---
async function getAIAnalysis(url, safe, threatType) {
    try {
        const prompt = `You are a cybersecurity expert. Analyze the URL: ${url}. 
        The Google Safe Browsing API reports: ${safe === true ? 'no threats' : (safe === false ? `threat detected: ${threatType}` : 'unknown status')}. 
        Provide a concise, helpful safety analysis (2-3 sentences) for a general user. Keep it in plain English.`;
        const completion = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: [{ role: "user", content: prompt }],
            max_tokens: 120,
            temperature: 0.5
        });
        return completion.choices[0].message.content.trim();
    } catch (err) {
        console.error('OpenAI error:', err.message);
        return "AI analysis temporarily unavailable.";
    }
}

// --- Save scan to DB ---
async function saveScan(url, verdict, threatType, aiAnalysis) {
    await pool.query(
        `INSERT INTO scans (url, verdict, threat_type, ai_analysis) VALUES ($1, $2, $3, $4)`,
        [url, verdict, threatType || null, aiAnalysis || null]
    );
}

// --- Check for cached scan ---
async function getCachedScan(url) {
    const res = await pool.query(
        `SELECT verdict, threat_type, ai_analysis, created_at FROM scans WHERE url = $1 ORDER BY created_at DESC LIMIT 1`,
        [url]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    const age = Date.now() - new Date(row.created_at).getTime();
    const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
    if (age > CACHE_TTL) return null;
    return {
        safe: row.verdict === 'safe',
        threatType: row.threat_type,
        aiAnalysis: row.ai_analysis,
        cached: true
    };
}

// --- Express middleware ---
app.use(express.json());
app.use(express.static('public')); // serve frontend (place index.html in public folder)

// --- API endpoints ---
app.post('/api/scan', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    // 1. Check cache
    const cached = await getCachedScan(url);
    if (cached) {
        return res.json({
            url,
            safe: cached.safe,
            threatType: cached.threatType,
            aiAnalysis: cached.aiAnalysis,
            cached: true
        });
    }

    // 2. Safe Browsing lookup
    const sbResult = await checkSafeBrowsing(url);
    let safe = sbResult.safe;
    let threatType = sbResult.threatType;

    // 3. If Safe Browsing returned null (unknown), treat as unknown
    let verdict = 'unknown';
    if (safe === true) verdict = 'safe';
    else if (safe === false) verdict = 'unsafe';

    // 4. AI analysis (always run, but we'll store)
    const aiAnalysis = await getAIAnalysis(url, safe, threatType);

    // 5. Save to DB
    await saveScan(url, verdict, threatType, aiAnalysis);

    // 6. Return result
    res.json({
        url,
        safe: safe === true ? true : (safe === false ? false : null),
        threatType,
        aiAnalysis,
        cached: false
    });
});

app.get('/api/history', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const result = await pool.query(
        `SELECT url, verdict, threat_type, ai_analysis, created_at FROM scans ORDER BY created_at DESC LIMIT $1`,
        [limit]
    );
    res.json(result.rows.map(row => ({
        url: row.url,
        verdict: row.verdict,
        threatType: row.threat_type,
        aiAnalysis: row.ai_analysis,
        created_at: row.created_at
    })));
});

// --- Start server ---
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log('👉 Place index.html in /public folder');
});