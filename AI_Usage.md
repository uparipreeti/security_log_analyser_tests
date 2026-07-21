## AI Usage and Collaboration

AI LLM assistance was used during project set-up, structuring, including reports, pair programming and debugging tests for failure
** Refining project structure for adding tests, parsering log details
** Adding edge cases which was missed during manual tests adding
** Debugging failed tests to diagonse configuration mismtaches
** Updating authLogs for malformed logs that was silently ignoring '[' for trimmed lines
** Refactoring before hooks to be accessible for all tests instead of inside one describe test block

*NOTE - language selection to write tests, adding manual tests except edge cases were manually verified and refined.*

** AI usage links: https://gemini.google.com/app/639bffdc5d734e83
** AI USage texts: "Based on my understanding the incidents in this logs report 4 failed attempts from webserver.log and ssh logs for login and then accepted which are co-related
2. single attempts logs: 172.16.0.20, 10.0.0.9910.0.0.88, sudo: johndoe :
3. false positive: 192.168.1.14,  Jul  3 10:00:20 server sudo: deploy :

I have identified these cases for logs along with brute force. Now, my framework project structure is Javascript with Mocha/chai assertions. Can you build me a framework which I can utilise along with Readme instructions. 
Readme includes: steps for installation, project structure, steps to run tests
AI_Usage.md - 
Test strategy - cover testing types except unit tests. "

"I would like to refine src/parser.js and analyzer.js into a folder strcuture as src/parsers/webserverParser.js and src/parsers/authParser.js. also include report generation under utils which shows passed and failed tests  count"

"package.json should be refined to include additional scripts: test:analyser_tests: npm run test:analyser"

"Edge cases for empty log, malformed logs are missng. can we add those tests as well"

"========================================
 TOTAL PASSED TESTS : 0
 TOTAL FAILED TESTS : 5
 TOTAL TESTS RUN    : 5

All tests failed. the logs is not being read correctly "

"TypeError: Cannot read properties of undefined (reading 'webLogs')"

"tests should be const parsed = parseWebServerLog(webLogPath);
        expect(parsed).to.be.an('array').that.is.not.empty;
        const malformedChecks = parsed.find(
            l =>(l.raw || l).includes('system restart'));
not onst malformedChecks = analyser.weblogs.find( "

"Also, I've noticed our tests miss auth.log tests specific"

"move the Before all hook so that it can be accessed by all tests. "

