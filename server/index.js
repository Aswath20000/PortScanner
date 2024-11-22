const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Socket } = require('net');
const ping = require('ping');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
require('dotenv').config();

mongoose.connect('mongodb://localhost:27017/network-scan', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('MongoDB connection error:', err);
});

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: 'http://localhost:3000', // Allow frontend's origin
        methods: ['GET', 'POST'],
        credentials: true
    }
});

const PORT = process.env.PORT || 5000;
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(bodyParser.json());

// Multer configuration for file upload
const upload = multer({ dest: 'uploads/' });

io.on('connection', (socket) => {
    console.log('A client connected to Socket.IO');
});

// --- Ping an IP Address ---
app.post('/ping', async (req, res) => {
    const { ipAddress } = req.body;

    if (!ipAddress) {
        return res.status(400).json({ error: 'IP Address is required' });
    }

    try {
        const pingResponse = await ping.promise.probe(ipAddress);
        res.json({
            ipAddress,
            alive: pingResponse.alive,
            time: pingResponse.time,
            output: pingResponse.output,
        });
    } catch (error) {
        res.status(500).json({ error: 'Error pinging IP Address', details: error.message });
    }
});

// --- Port Scan ---
app.post('/scan-ports', async (req, res) => {
    const { ipAddress, portRange } = req.body;

    if (!ipAddress || !portRange || portRange.start > portRange.end) {
        return res.status(400).json({ error: 'Invalid input data for port scan' });
    }

    const openPorts = [];
    const timeout = 10000;

    try {
        for (let port = portRange.start; port <= portRange.end; port++) {
            console.log(`Scanning port: ${port}`); // Log the port being scanned

            await new Promise((resolve) => {
                const sock = new Socket();
                sock.setTimeout(timeout);

                sock
                    .on('connect', () => {
                        console.log(`Port ${port} is open`); // Log if the port is open
                        openPorts.push(port);
                        io.emit('scan-progress', { port, status: 'open' });
                        sock.destroy();
                        resolve();
                    })
                    .on('error', () => {
                        console.log(`Port ${port} is closed`); // Log if the port is closed
                        io.emit('scan-progress', { port, status: 'closed' });
                        sock.destroy();
                        resolve();
                    })
                    .on('timeout', () => {
                        console.log(`Port ${port} timed out`); // Log if the port times out
                        io.emit('scan-progress', { port, status: 'timeout' });
                        sock.destroy();
                        resolve();
                    })
                    .connect(port, ipAddress);
            });
        }
        console.log('Port scan completed'); // Log when the scan is finished
        io.emit('scan-completed', openPorts);
        res.json({ openPorts });
    } catch (error) {
        console.error('Error during port scan:', error); // Log any errors
        res.status(500).json({ error: 'Error during port scan' });
    }
});

// --- Network Scan ---
app.post('/scan-network', async (req, res) => {
    const { subnet } = req.body;

    if (!subnet || !subnet.match(/^(\d{1,3}.\d{1,3}\.\d{1,3}\.)$/)) {
        return res.status(400).json({ error: 'Please provide a valid subnet in the format 192.168.1.' });
    }

    const activeDevices = [];

    const scanNetwork = async () => {
        for (let i = 1; i <= 255; i++) {
            const targetIp = `${subnet}${i}`;
            console.log(`Pinging IP: ${targetIp}`);
            const pingResponse = await ping.promise.probe(targetIp, { timeout: 1 });

            if (pingResponse.alive) {
                activeDevices.push(targetIp);
                io.emit('network-scan-progress', targetIp); // Emit each active device to frontend as it’s found
            }
        }
        io.emit('network-scan-completed', activeDevices); // Emit completed list of active devices
    };

    try {
        await scanNetwork();
        res.json({ activeDevices });
    } catch (error) {
        res.status(500).json({ error: 'Network scan failed', details: error.message });
    }
});

// --- VirusTotal Scan ---
app.post('/scan-file', upload.single('file'), async (req, res) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY; // VirusTotal API Key
    if (!apiKey) {
        return res.status(500).json({ error: 'VirusTotal API key is not configured.' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    try {
        const filePath = req.file.path;
        console.log(`Uploading file to VirusTotal: ${req.file.originalname}`);

        // Upload the file to VirusTotal
        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));

        const response = await axios.post('https://www.virustotal.com/api/v3/files', formData, {
            headers: {
                'x-apikey': apiKey,
                ...formData.getHeaders(),
            },
        });

        const fileId = response.data.data.id;
        console.log(`File uploaded successfully. File ID: ${fileId}`);

        // Retrieve scan report
        const reportResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${fileId}`, {
            headers: {
                'x-apikey': apiKey,
            },
        });

        const scanResults = reportResponse.data.data.attributes.last_analysis_results;

        // Check if any antivirus flagged the file as malware
        const malwareFound = Object.entries(scanResults).filter(([engine, result]) => result.category === 'malicious');
        
        if (malwareFound.length > 0) {
            const maliciousDetails = malwareFound.map(([engine, result]) => ({
                engine: engine,
                verdict: result.category,
                description: result.result,
            }));
            console.log('Malware detected in the file:', maliciousDetails);
            res.json({ message: 'Malware detected', details: maliciousDetails });
        } else {
            console.log('No malware detected.');
            res.json({ message: 'No malware detected' });
        }

        // Clean up uploaded file
        fs.unlinkSync(filePath);
    } catch (error) {
        console.error('Error during VirusTotal scan:', error.response?.data || error.message);
        res.status(500).json({ error: 'Error during VirusTotal scan', details: error.message });
    }
});

