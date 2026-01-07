require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');

const app = express();

// Security: Helmet for various HTTP headers
app.use(helmet());

// Security: CORS - Only allow specific origins
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:5173'];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Security: API Key Middleware
const apiKeyAuth = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({ error: 'Unauthorized: Invalid API key' });
    }

    next();
};

// Security: File Upload Configuration with limits
const upload = multer({
    dest: 'uploads/',
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB max
        files: 1 // Only 1 file at a time
    },
    fileFilter: (req, file, cb) => {
        // Only accept CSV files
        const allowedMimes = ['text/csv', 'application/vnd.ms-excel', 'text/plain'];
        if (allowedMimes.includes(file.mimetype) || file.originalname.endsWith('.csv')) {
            cb(null, true);
        } else {
            cb(new Error('Only CSV files are allowed'));
        }
    }
});

// Security: Rate Limiters
const generalLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100, // 100 requests per window
    message: 'Too many requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Max 10 uploads per 15 minutes
    message: 'Too many uploads, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const editLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 90, // Max 30 edits per 5 minutes
    message: 'Too many edit requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply general rate limiter to all routes
app.use(generalLimiter);

// Helper: Chunk array into smaller batches
function chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
        chunks.push(array.slice(i, i + size));
    }
    return chunks;
}

// Helper: Sanitize text input
function sanitizeText(text) {
    if (!text) return '';
    // Remove special characters that could be used for XSS
    return validator.escape(text.trim());
}

// Endpoint: Upload CSV (Protected with Auth + Rate Limit)
app.post('/upload-csv', apiKeyAuth, uploadLimiter, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    const filePath = req.file.path;
    const results = [];

    fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (data) => results.push(data))
        .on('end', async () => {
            try {
                // Step 1: Parse and collect unique words
                const enWordsSet = new Set();
                const idWordsSet = new Set();
                const pairs = [];

                for (const row of results) {
                    const enKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'en');
                    const idKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'id');
                    if (!enKey || !idKey) continue;

                    const enWord = sanitizeText(row[enKey]);
                    const idWord = sanitizeText(row[idKey]);

                    // Validate length
                    if (!enWord || !idWord || enWord.length > 255 || idWord.length > 255) continue;

                    enWordsSet.add(enWord);
                    idWordsSet.add(idWord);
                    pairs.push({ en: enWord, id: idWord });
                }

                const enWordsArray = Array.from(enWordsSet);
                const idWordsArray = Array.from(idWordsSet);

                console.log(`Processing ${pairs.length} pairs, ${enWordsArray.length} unique EN, ${idWordsArray.length} unique ID`);

                // Step 2: Bulk upsert English words (in chunks of 500)
                const enChunks = chunkArray(enWordsArray.map(w => ({ en_word: w })), 500);
                for (const chunk of enChunks) {
                    const { error } = await supabase
                        .from('english')
                        .upsert(chunk, { onConflict: 'en_word', ignoreDuplicates: true });
                    if (error) console.error('EN upsert error:', error.message);
                }

                // Step 3: Bulk upsert Indonesian words (in chunks of 500)
                const idChunks = chunkArray(idWordsArray.map(w => ({ id_word: w })), 500);
                for (const chunk of idChunks) {
                    const { error } = await supabase
                        .from('indonesia')
                        .upsert(chunk, { onConflict: 'id_word', ignoreDuplicates: true });
                    if (error) console.error('ID upsert error:', error.message);
                }

                // Step 4: Fetch all English IDs
                const enMap = new Map();
                const enFetchChunks = chunkArray(enWordsArray, 500);
                for (const chunk of enFetchChunks) {
                    const { data, error } = await supabase
                        .from('english')
                        .select('id, en_word')
                        .in('en_word', chunk);
                    if (error) console.error('EN fetch error:', error.message);
                    if (data) {
                        data.forEach(row => enMap.set(row.en_word, row.id));
                    }
                }

                // Step 5: Fetch all Indonesian IDs
                const idMap = new Map();
                const idFetchChunks = chunkArray(idWordsArray, 500);
                for (const chunk of idFetchChunks) {
                    const { data, error } = await supabase
                        .from('indonesia')
                        .select('id, id_word')
                        .in('id_word', chunk);
                    if (error) console.error('ID fetch error:', error.message);
                    if (data) {
                        data.forEach(row => idMap.set(row.id_word, row.id));
                    }
                }

                // Step 6: Build relations array
                const relationsToInsert = [];
                const seenRelations = new Set();

                for (const pair of pairs) {
                    const enId = enMap.get(pair.en);
                    const idId = idMap.get(pair.id);
                    if (enId && idId) {
                        const key = `${enId}-${idId}`;
                        if (!seenRelations.has(key)) {
                            seenRelations.add(key);
                            relationsToInsert.push({
                                id_english: enId,
                                id_indonesia: idId,
                                success: 'N'
                            });
                        }
                    }
                }

                // Step 7: Bulk insert relations
                let insertedCount = 0;
                const relChunks = chunkArray(relationsToInsert, 500);
                for (const chunk of relChunks) {
                    const { data, error } = await supabase
                        .from('right_guess')
                        .upsert(chunk, { onConflict: 'id_english,id_indonesia', ignoreDuplicates: true })
                        .select();

                    if (error) {
                        const { data: insertData, error: insertError } = await supabase
                            .from('right_guess')
                            .insert(chunk)
                            .select();
                        if (!insertError && insertData) {
                            insertedCount += insertData.length;
                        }
                    } else if (data) {
                        insertedCount += data.length;
                    }
                }

                console.log(`Done! Inserted ${insertedCount} new relations.`);
                res.json({ message: 'CSV processed successfully', count: insertedCount });

            } catch (error) {
                console.error('Processing error:', error);
                const errorMessage = process.env.NODE_ENV === 'production'
                    ? 'Error processing CSV file'
                    : error.message;
                res.status(500).json({ error: errorMessage });
            } finally {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            }
        })
        .on('error', (error) => {
            console.error('CSV parsing error:', error);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            res.status(400).json({ error: 'Invalid CSV file format' });
        });
});

// Endpoint: Get Random Word (No auth needed for reading)
app.get('/word', async (req, res) => {
    try {
        const { count } = await supabase.from('right_guess').select('*', { count: 'exact', head: true });
        if (count === null || count === 0) return res.status(404).json({ error: 'No words found' });

        const randomIndex = Math.floor(Math.random() * count);

        const { data, error } = await supabase
            .from('right_guess')
            .select(`
        id,
        id_english,
        id_indonesia,
        success,
        english (en_word),
        indonesia (id_word)
      `)
            .range(randomIndex, randomIndex)
            .single();

        if (error) throw error;
        res.json(data);
    } catch (error) {
        console.error('Fetch word error:', error);
        const errorMessage = process.env.NODE_ENV === 'production'
            ? 'Error fetching word'
            : error.message;
        res.status(500).json({ error: errorMessage });
    }
});

// Endpoint: Update Word (Protected with Auth + Rate Limit)
app.put('/word/:id', apiKeyAuth, editLimiter, async (req, res) => {
    const { id } = req.params;
    const { en_word, id_word } = req.body;

    // Validate ID
    if (!validator.isInt(id)) {
        return res.status(400).json({ error: 'Invalid ID' });
    }

    try {
        const { data: rel, error: relError } = await supabase
            .from('right_guess')
            .select('id_english, id_indonesia')
            .eq('id', id)
            .single();

        if (relError || !rel) {
            return res.status(404).json({ error: 'Word relation not found' });
        }

        if (en_word) {
            const sanitized = sanitizeText(en_word);
            if (sanitized.length > 255) {
                return res.status(400).json({ error: 'English word too long' });
            }
            await supabase.from('english').update({ en_word: sanitized }).eq('id', rel.id_english);
        }

        if (id_word) {
            const sanitized = sanitizeText(id_word);
            if (sanitized.length > 255) {
                return res.status(400).json({ error: 'Indonesian word too long' });
            }
            await supabase.from('indonesia').update({ id_word: sanitized }).eq('id', rel.id_indonesia);
        }

        res.json({ success: true });
    } catch (e) {
        console.error('Update word error:', e);
        const errorMessage = process.env.NODE_ENV === 'production'
            ? 'Error updating word'
            : e.message;
        res.status(500).json({ error: errorMessage });
    }
});

// Endpoint: Update Status (Protected with Auth)
app.post('/word/:id/status', apiKeyAuth, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    // Validate inputs
    if (!validator.isInt(id)) {
        return res.status(400).json({ error: 'Invalid ID' });
    }

    if (!['Y', 'X', 'N'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Must be Y, X, or N' });
    }

    try {
        const { error } = await supabase
            .from('right_guess')
            .update({ success: status })
            .eq('id', id);

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Update status error:', error);
        const errorMessage = process.env.NODE_ENV === 'production'
            ? 'Error updating status'
            : error.message;
        res.status(500).json({ error: errorMessage });
    }
});

// Cleanup function
function cleanupUploadsFolder() {
    const uploadsDir = './uploads';

    if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
        console.log('Created uploads folder');
        return;
    }

    const files = fs.readdirSync(uploadsDir);
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    let deletedCount = 0;

    files.forEach(file => {
        const filePath = `${uploadsDir}/${file}`;
        try {
            const stats = fs.statSync(filePath);
            if (stats.mtimeMs < oneHourAgo) {
                fs.unlinkSync(filePath);
                deletedCount++;
                console.log(`Deleted old file: ${file}`);
            }
        } catch (err) {
            console.error(`Error processing file ${file}:`, err.message);
        }
    });

    if (deletedCount > 0) {
        console.log(`Cleanup complete: Removed ${deletedCount} old file(s)`);
    } else {
        console.log('Cleanup complete: No old files to remove');
    }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔒 Security: API Key authentication enabled`);
    console.log(`🌐 CORS allowed origins: ${allowedOrigins.join(', ')}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);

    cleanupUploadsFolder();
});
