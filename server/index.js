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

mongoose.connect('mongodb://localhost:27017/networkToolData', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('MongoDB connection error:', err);
});

const ScanLogSchema = new mongoose.Schema({
    ipAddress: String,
    subnet: String,
    fileName: String,
    scanType: String,
    timestamp: { type: Date, default: Date.now },
    result: mongoose.Schema.Types.Mixed,
});

const ScanLog = mongoose.model('ScanLog', ScanLogSchema);

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: 'http://localhost:3000',
        methods: ['GET', 'POST'],
        credentials: true
    }
});

const PORT = process.env.PORT || 5000;

app.use(cors({ origin: 'http://localhost:3000' }));
app.use(bodyParser.json());

const upload = multer({ 
    dest: 'uploads/', 
    limits: { fileSize: 10 * 1024 * 1024 } 
});

if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

io.on('connection', (socket) => {
    console.log('A client connected to Socket.IO');
});

app.post('/ping', async (req, res) => {
    const { ipAddress } = req.body;

    if (!ipAddress) {
        return res.status(400).json({ error: 'IP Address is required' });
    }

    try {
        const pingResponse = await ping.promise.probe(ipAddress);

        const logEntry = new ScanLog({
            ipAddress,
            scanType: 'ping',
            result: pingResponse,
        });
        await logEntry.save();

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

app.post('/scan-ports', async (req, res) => {
    const { ipAddress, portRange } = req.body;

    if (!ipAddress || !portRange || portRange.start > portRange.end) {
        return res.status(400).json({ error: 'Invalid input data for port scan' });
    }

    const openPorts = [];
    const timeout = 10000;

    try {
        for (let port = portRange.start; port <= portRange.end; port++) {
            await new Promise((resolve) => {
                const sock = new Socket();
                sock.setTimeout(timeout);

                sock
                    .on('connect', () => {
                        openPorts.push(port);
                        io.emit('scan-progress', { port, status: 'open' });
                        sock.destroy();
                        resolve();
                    })
                    .on('error', () => {
                        io.emit('scan-progress', { port, status: 'closed' });
                        sock.destroy();
                        resolve();
                    })
                    .on('timeout', () => {
                        io.emit('scan-progress', { port, status: 'timeout' });
                        sock.destroy();
                        resolve();
                    })
                    .connect(port, ipAddress);
            });
        }

        const logEntry = new ScanLog({
            ipAddress,
            scanType: 'port-scan',
            result: openPorts,
        });
        await logEntry.save();

        io.emit('scan-completed', openPorts);
        res.json({ openPorts });
    } catch (error) {
        res.status(500).json({ error: 'Error during port scan', details: error.message });
    }
});

app.post('/scan-network', async (req, res) => {
    const { subnet } = req.body;

    if (!subnet || !subnet.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)$/)) {
        return res.status(400).json({ error: 'Please provide a valid subnet in the format 192.168.1.' });
    }

    const activeDevices = [];

    const scanNetwork = async () => {
        for (let i = 1; i <= 255; i++) {
            const targetIp = `${subnet}${i}`;
            console.log(targetIp);
            const pingResponse = await ping.promise.probe(targetIp, { timeout: 1 });

            if (pingResponse.alive) {
                activeDevices.push(targetIp);
                io.emit('network-scan-progress', targetIp);
            }
        }
        io.emit('network-scan-completed', activeDevices);
    };

    try {
        await scanNetwork();

        const logEntry = new ScanLog({
            subnet,
            scanType: 'network-scan',
            result: activeDevices,
        });
        await logEntry.save();

        res.json({ activeDevices });
    } catch (error) {
        res.status(500).json({ error: 'Network scan failed', details: error.message });
    }
});
app.post('/scan-file', upload.single('file'), async (req, res) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
        return res.status(500).json({ error: 'VirusTotal API key is not configured.' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    try {
        const filePath = req.file.path;

        if (!fs.existsSync(filePath)) {
            return res.status(400).json({ error: `Uploaded file not found at ${filePath}` });
        }

        
        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));

        const headers = {
            'x-apikey': apiKey,
            ...formData.getHeaders(),
        };

        const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', formData, { headers });
        console.log('VirusTotal upload response:', uploadResponse.data);

        if (!uploadResponse || !uploadResponse.data || !uploadResponse.data.data.id) {
            return res.status(500).json({ error: 'Invalid response from VirusTotal during file upload.' });
        }

        const fileId = uploadResponse.data.data.id;
        let retries = 5;
        let reportResponse;

        
        while (retries > 0) {
            try {
                reportResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${fileId}`, {
                    headers: { 'x-apikey': apiKey },
                });
                console.log('VirusTotal analysis response:', reportResponse.data);

                if (reportResponse?.data?.data?.attributes?.status === 'completed') {
                    break;
                }
            } catch (error) {
                console.error('Error fetching VirusTotal analysis:', error.response?.data || error.message);
            }
            await new Promise((resolve) => setTimeout(resolve, 5000));
            retries--;
        }

        if (retries === 0 || !reportResponse?.data?.data?.attributes) {
            return res.status(500).json({ error: 'Failed to retrieve scan results from VirusTotal after retries.' });
        }

        
        const scanResults = reportResponse.data.data.attributes.results || {};
        const maliciousDetails = Object.entries(scanResults).filter(
            ([engine, result]) => result?.category === 'malicious'
        );

        
        fs.unlinkSync(filePath);

    
        const logEntry = new ScanLog({
            fileName: req.file.originalname,
            scanType: 'file-scan',
            result: maliciousDetails.length > 0
                ? { message: 'Malware detected', details: maliciousDetails }
                : { message: 'No malware detected' },
        });
        await logEntry.save();

        res.json(logEntry.result);
    } catch (error) {
        console.error('Error during VirusTotal scan:', error.response?.data || error.message);
        res.status(500).json({ error: 'Error during VirusTotal scan', details: error.message });
    }
});






server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
