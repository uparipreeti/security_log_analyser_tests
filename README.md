# security_log_analyser_tests
Command-line tool to detect potential security incidents from webserver logs and authentication logs

###QA Strategy Approach

## Understaning of Requirements
1. Process two different log formats(webserver.log and auth.logs)
2. Detect attacks
3. Upport confugurable rules
4. SQL injections
5. handle malformed entries
6. Provide clear, actionable output

## Test Strategy
***Testing types covered: Integration testing, end-to-end testing***
#Integration tests: 
1. Full analysis on provided logs
2. Co-relations of logs
3. Error handling when one file succeeds and other fails
4. multiple files processed togeter

## End to End testing
1. Test complete user flow with this tool
2. Run with single file
3. Run with both sample logs
4. Run with custom rule file
5. Run with invalid paths

## Project Structure
- `src/parsers/authParsers.js`: Parses raw text inputs for web and auth logs, discarding malformed entries safely.
- `src/parsers/webserverParser.js`: Core correlation and rule detection engine handling brute-force tracking, recon detection, and false positive segregation.
- `test/`: Contains functional, integration, and system tests (excluding unit tests).
- `logs/`: Placement directory for log inputs (`webserver.log`, `auth.log`).

## Steps for Installation
1. Ensure you have **Node.js** installed (version 16+ recommended).
2. Clone or download this project directory: 
3. Install project dependencies:
   ```bash
   npm install


