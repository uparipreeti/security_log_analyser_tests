# security_log_analyser_tests
Command-line tool to detect potential security incidents from webserver logs and authentication logs

#QA Strategy Approach

#Understaning of Requirements
1. Process two different log formats(webserver.log and auth.logs)
2. Detect attacks
3. Upport confugurable rules
4. SQL injections
5. handle malformed entries
6. Provide clear, actionable output

#Test Strategy
#Integration tests: 
1. Full analysis on provided logs
2. Co-relations of logs
3. Error handling when one file succeeds and other fails
4. multiple files processed togeter

#End to End testing
1. Test complete user flow with this tool
2. Run with single file
3. Run with both sample logs
4. Run with custom rule file
5. Run with invalid paths
6. 


