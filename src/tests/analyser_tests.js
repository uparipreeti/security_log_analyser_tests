const { expect }= require ('chai');
const fs = require('fs');
const SecurityAnalyser = require('../analyser')
const path = require('path');
const { parseWebServerLog } = require('../parsers/webserverParser');
const { parseAuthLog } = require('../parsers/authParsers');

let analyser;
    const webLogPath = path.resolve(__dirname, '../logs/webserver.log');
    const authLogPath = path.resolve(__dirname, '../logs/auth.log');
    const emptyLogPath = path.resolve(__dirname, 'temp_empty.log');
    const malformedAuthLogPath = path.resolve(__dirname, 'temp_malformed_auth.log');
 
describe('Security Analysis tests', () =>{
    before(() => {
        fs.writeFileSync(emptyLogPath, '');
        fs.writeFileSync(
            malformedAuthLogPath,
            `Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2\n[CORRUPTED ENTRY - binary payload garbage\nJul  3 10:00:15 server sudo: johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow\n`
        );

    });

    after(() => {
        if (fs.existsSync(emptyLogPath)) fs.unlinkSync(emptyLogPath);
        if (fs.existsSync(malformedAuthLogPath)) fs.unlinkSync(malformedAuthLogPath);
        
    });

    // Helper to safely call whichever method name is defined on your class
    function runAnalysis(instance) {
        if (typeof instance.analyze === 'function') return instance.analyze();
        if (typeof instance.analyse === 'function') return instance.analyse();
        throw new Error('Neither analyze() nor analyse() method found on SecurityAnalyser');
    }

describe('Functional testing : Log parsing and detection rules', () => {
    it('Positive- it should correctly parse weberver logs and skip malformed logs', ()=> {
        const parsed = parseWebServerLog(webLogPath);
        expect(parsed).to.be.an('array').that.is.not.empty;
        const malformedChecks = parsed.find(
            l =>(l.raw || l).includes('system restart'));
        expect(malformedChecks).to.be.undefined;
    });

    it('Positive- it should detect corelate logs for login attempts 10.0.0.50', () => {
        const analyser = new SecurityAnalyser(webLogPath, authLogPath);
        const report = runAnalysis(analyser);
        const bruteForce = report.incidents.find(i =>
            i.type=== 'CORRELATED_BRUTE_FORCE'
        );
        
        expect(bruteForce).to.not.be.undefined;
        expect(bruteForce.ip || bruteForce.sourceIp).to.be.equal('10.0.0.50');
    });

    it('Positive-should detect SQL Injection attempt from 10.0.0.88', () => {
        const analyser = new SecurityAnalyser(webLogPath, authLogPath);
        const report = runAnalysis(analyser);
        const sqli = report.incidents.find(i => i.type === 'SQL_INJECTION');

        expect(sqli).to.not.be.undefined;
        expect(sqli.sourceIp || sqli.ip).to.equal('10.0.0.88');
    });

    it('Negative-should flag false positive user query for 192.168.1.14', () => {
        const analyser = new SecurityAnalyser(webLogPath, authLogPath);
        const report = runAnalysis(analyser);
        const fp = report.falsePositivesIdentified.find(f => f.ip === '192.168.1.14');

        expect(fp).to.not.be.undefined;
    });

    it('should handle empty log files gracefully without crashing', () => {
        const analyser = new SecurityAnalyser(emptyLogPath, emptyLogPath);
        const report = runAnalysis(analyser);
        expect(report.incidents).to.be.an('array').that.is.empty;
    });

});

describe('Auth Log Parser Tests', () => {
    const authLogPath = path.resolve(__dirname, '../logs/auth.log');
    const malformedAuthLogPath = path.resolve(__dirname, 'temp_malformed_auth.log');

    it('should correctly parse valid auth.log entries', () => {
        const parsed = parseAuthLog(authLogPath);
        expect(parsed).to.be.an('array').that.is.not.empty;
        
        const failedSshEntry = parsed.find(l => (l.raw || l).includes('Failed password for admin'));
        expect(failedSshEntry).to.not.be.undefined;
    });

    it('should identify sudo commands executed by users in auth.log', () => {
        const parsed = parseAuthLog(authLogPath);
        const johnDoeSudo = parsed.find(l => (l.raw || l).includes('sudo: johndoe'));
        const deploySudo = parsed.find(l => (l.raw || l).includes('sudo: deploy'));

        expect(johnDoeSudo).to.not.be.undefined;
        expect(deploySudo).to.not.be.undefined;
    });

    it('should ignore corrupted/malformed auth entries', () => {
        const parsed = parseAuthLog(malformedAuthLogPath);
        expect(parsed).to.have.lengthOf(2);

        const corruptedEntry = parsed.find(l => (l.raw || l).includes('CORRUPTED'));
        expect(corruptedEntry).to.be.undefined;
    });

});

describe('Integration testing - Test corelation between auth and webserver logs', () => {
    it('should correlate webserver login tracking with auth.log SSH events seamlessly', () => {
        const webPath = path.join(__dirname, '../logs/webserver.log');
        const authPath = path.join(__dirname, '../logs/auth.log');
        const analyser = new SecurityAnalyser(webPath, authPath);

        const results = analyser.analyse();
        expect(results.incidents).to.be.an('array');
        
        // Ensure multi-source correlation engine outputs structured analysis
        const correlatedIncidents = results.incidents.filter(i => i.sourceIp === '10.0.0.50');
        expect(correlatedIncidents.length).to.equal(1);
    });
});

describe('System/end-to-end testing - Test corelation between auth and webserver logs', () => {
    it('should process inputs, execute complete detection pipeline, and handle false positives correctly', () => {
        const webPath = path.join(__dirname, '../logs/webserver.log');
        const authPath = path.join(__dirname, '../logs/auth.log');
        
        const analyser = new SecurityAnalyser(webPath, authPath);
        const report = analyser.analyse();

        // Verify False Positives (e.g., 192.168.1.14 O'Brien query) are properly categorized
        const fpMatch = report.falsePositivesIdentified.find(fp => fp.ip === '192.168.1.14');
        expect(fpMatch).to.not.be.undefined;
        
        // Verify output report layout is complete and actionable
        expect(report).to.have.property('incidents');
        expect(report.incidents.length).to.be.greaterThan(0);
    });
});
});






