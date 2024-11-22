import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import './App.css';

const socket = io('http://localhost:5000', {
    withCredentials: true
});

function App() {
    const [ipAddress, setIpAddress] = useState('');
    const [portRange, setPortRange] = useState({ start: 1, end: 1024 });
    const [subnet, setSubnet] = useState('');
    const [pingResult, setPingResult] = useState(null);
    const [isPinging, setIsPinging] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [scanProgress, setScanProgress] = useState([]);
    const [portResults, setPortResults] = useState([]);
    const [activeDevices, setActiveDevices] = useState([]);
    const [file, setFile] = useState(null);
    const [fileScanResult, setFileScanResult] = useState(null);

    useEffect(() => {
        socket.on('scan-progress', (data) => {
            setScanProgress((prev) => [...prev, data]);
        });

        socket.on('scan-completed', (openPorts) => {
            setPortResults(openPorts);
            setScanProgress([]);
        });

        socket.on('network-scan-progress', (data) => {
            setActiveDevices((prev) => [...prev, data]);
        });

        socket.on('network-scan-completed', (devices) => {
            setActiveDevices(devices);
        });

        return () => {
            socket.off('scan-progress');
            socket.off('scan-completed');
            socket.off('network-scan-progress');
            socket.off('network-scan-completed');
        };
    }, [ipAddress]);

    const handlePing = async () => {
        setIsPinging(true);
        try {
            const response = await axios.post('http://localhost:5000/ping', { ipAddress });
            setPingResult(response.data);
        } catch (error) {
            alert(error.response?.data?.error || 'Error pinging IP Address');
        } finally {
            setIsPinging(false);
        }
    };

    const handlePortScan = async () => {
        setIsScanning(true);
        setPortResults([]);
        setScanProgress([]);
        try {
            await axios.post('http://localhost:5000/scan-ports', { ipAddress, portRange });
        } catch (error) {
            alert(error.response?.data?.error || 'Error scanning ports');
        } finally {
            setIsScanning(false);
        }
    };

    const handleNetworkScan = async () => {
        try {
            await axios.post('http://localhost:5000/scan-network', { subnet });
        } catch (error) {
            alert(error.response?.data?.error || 'Error scanning network');
        }
    };

    const handleFileUpload = async () => {
        if (!file) return alert('Please select a file to upload.');
    
        const formData = new FormData();
        formData.append('file', file);
    
        try {
            const response = await axios.post('http://localhost:5000/scan-file', formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
            });
    
            if (response.data.message === 'Malware detected') {
                setFileScanResult({
                    message: 'Malware detected',
                    details: response.data.details,
                });
            } else {
                setFileScanResult({
                    message: 'No malware detected',
                    details: [],
                });
            }
        } catch (error) {
            alert(error.response?.data?.error || 'Error scanning file');
        }
    };

    return (
        <div className="App">
            <h1>Network Tools</h1>

            
            <div id="Ping" className='card'>
                <h2>Ping IP</h2>
                <input value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="Enter IP" />
                <button onClick={handlePing} disabled={isPinging}>
                    {isPinging ? 'Pinging...' : 'Ping'}
                </button>
                {pingResult && <pre>{JSON.stringify(pingResult, null, 2)}</pre>}
            </div>

            
            <div id="Port" className='card'>
                <h2>Port Scan</h2>
                <input
                    type="number"
                    value={portRange.start}
                    onChange={(e) => setPortRange({ ...portRange, start: parseInt(e.target.value) })}
                    placeholder="Start Port"
                />
                <input
                    type="number"
                    value={portRange.end}
                    onChange={(e) => setPortRange({ ...portRange, end: parseInt(e.target.value) })}
                    placeholder="End Port"
                />
                <button onClick={handlePortScan} disabled={isScanning}>
                    {isScanning ? 'Scanning...' : 'Scan Ports'}
                </button>
                <ul>
                    {scanProgress.map((data, i) => (
                        <li key={i}>
                            Port {data.port}: {data.status}
                        </li>
                    ))}
                </ul>
                <h3>Open Ports:</h3>
                <ul>
                    {portResults.map((port, i) => (
                        <li key={i}>Port {port} is open</li>
                    ))}
                </ul>
            </div>

            
            <div id="Network" className='card'>
                <h2>Network Scan</h2>
                <input
                    value={subnet}
                    onChange={(e) => setSubnet(e.target.value)}
                    placeholder="Enter Subnet (e.g., 192.168.1.0/24)"
                />
                <button onClick={handleNetworkScan}>Scan Network</button>
                <h3>Active Devices:</h3>
                <ul>
                    {activeDevices.map((device, i) => (
                        <li key={i}>{device}</li>
                    ))}
                </ul>
            </div>

             
        <div id="Malware" className='card'>
            <h2>Upload File for Malware Scan</h2>
            <input type="file" onChange={(e) => setFile(e.target.files[0])} />
            <button onClick={handleFileUpload}>Upload and Scan</button>

            {fileScanResult && (
                <div>
                    <h3>{fileScanResult.message}</h3>
                    {fileScanResult.details.length > 0 && (
                        <ul>
                            {fileScanResult.details.map((item, index) => (
                                <li key={index}>
                                    <strong>{item.engine}</strong>: {item.verdict} - {item.description}
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            )}
        </div>
        </div>
    );
}

export default App;
