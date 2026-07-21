const fs = require('fs');

function parseAuthLog(filePath) {
    if (!fs.existsSync(filePath)) return [];

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const parsed = [];

    for (let line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('[')) continue;
        parsed.push({ raw: line });
    }
    return parsed;
}

module.exports = { parseAuthLog };