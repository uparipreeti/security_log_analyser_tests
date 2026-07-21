const fs = require('fs');

function parseWebServerLog(filePath) {
    if (!fs.existsSync(filePath)) return [];
    
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const parsed = [];

    for (let line of lines) {
        if (!line.trim() || line.startsWith('[MALFORMED')) continue;
        const match = line.match(/^(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+|-)$/);
        if (match) {
            parsed.push({
                raw: line,
                ip: match[1],
                timestamp: match[2],
                request: match[3],
                status: parseInt(match[4], 10),
                bytes: match[5]
            });
        }
    }
    return parsed;
}

module.exports = { parseWebServerLog };