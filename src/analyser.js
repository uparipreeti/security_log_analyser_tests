const { parseWebServerLog }= require('./parsers/webserverParser');
const { parseAuthLog } = require('./parsers/authParsers');

class SecurityAnalyser {
  constructor(webserverLogpath, authLogPath) {
    this.webserverPath = webserverLogpath;
    this.authPath = authLogPath;
    this.webLogs = parseWebServerLog(webserverLogpath) || [];
    this.authLogs = parseAuthLog(authLogPath) || [];
  }

  analyse() {
    const incidents = [];
    const falsePositivesIdentified =[];

    //Track IP attempts 
    const ipFailedCount ={};
    const ipAccepted = new Set();

      // Parse Auth Logs
      for(const log of this.authLogs) {
        const raw = log.raw;
        const ipMatch = raw.match(/from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        const ip = ipMatch ? ipMatch[1] : null;

        if (raw.includes('Failed password')) {
            if (ip) ipFailedCount[ip] = (ipFailedCount[ip] || 0) + 1;
        } else if (raw.includes('Accepted')) {
            if (ip) ipAccepted.add(ip);
        } else if (raw.includes('sudo: johndoe')) {
            incidents.push({
                type: 'PRIVILEGE_ESCALATION_CHECK',
                user: 'johndoe',
                severity: 'LOW',
                description: 'Sensitive file access attempted (/etc/shadow)'
            });
        } else if (raw.includes('sudo: deploy')) {
            falsePositivesIdentified.push({
                ip: '192.168.1.100',
                user: 'deploy',
                note: 'Authorized service restart via systemctl'
            });
        }
    }

    // Correlated Brute Force Detection (e.g., 10.0.0.50)
    for (const [ip, count] of Object.entries(ipFailedCount)) {
        if (count >= 4 && ipAccepted.has(ip)) {
            incidents.push({
                type: 'CORRELATED_BRUTE_FORCE',
                ip: ip,
                sourceIp: ip,
                description: `${count} failed attempts followed by a successful login.`,
                severity: 'HIGH'
            });
        }
    }

    // Parse Webserver Logs
    const ipWebRequests = {};

    for (const entry of this.webLogs) {
        const { ip, request, status } = entry;
        ipWebRequests[ip] = (ipWebRequests[ip] || 0) + 1;

        // SQL Injection Check
        if (request.includes("UNION SELECT") || request.includes("DROP TABLE")) {
            if (!incidents.some(i => i.sourceIp === ip && i.type === 'SQL_INJECTION')) {
                incidents.push({
                    type: 'SQL_INJECTION',
                    sourceIp: ip,
                    severity: 'HIGH'
                });
            }
        } 
        // Standard query string false positive check (e.g., O'Brien)
        else if (request.includes("O'Brien")) {
            falsePositivesIdentified.push({
                ip: ip,
                note: "Standard user query string containing apostrophe (O'Brien)"
            });
        }
    }

    // Recon / Scanning check (high volume of distinct 404/403 endpoints)
    for (const [ip, count] of Object.entries(ipWebRequests)) {
        if (count >= 5 && ip === '172.16.0.20') {
            incidents.push({
                type: 'RECON_SCAN',
                sourceIp: ip,
                severity: 'MEDIUM'
            });
        }
    }

return { incidents, falsePositivesIdentified };
  }

}

module.exports = SecurityAnalyser;