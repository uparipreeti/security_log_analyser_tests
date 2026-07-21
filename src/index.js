#!/usr/bin/env node

const path = require('path');
const { runAnalysis } = require('./analyzer');
const { generateReport } = require('./utils/reporter');

function parseArgs(argv) {
  const args = { format: 'text' };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--webserver-log') args.webserverLogPath = argv[++i];
    else if (arg === '--auth-log') args.authLogPath = argv[++i];
    else if (arg === '--rules') args.rulesConfigPath = argv[++i];
    else if (arg === '--format') args.format = argv[++i];
    else if (arg === '--help' || arg === '-h') args.help = true;
  }
  return args;
}

function printHelp() {
  console.log(`
Security Log Analyzer

Usage:
  node src/index.js --webserver-log <path> --auth-log <path> [options]

Options:
  --webserver-log <path>   Path to the webserver access log (Combined Log Format)
  --auth-log <path>        Path to the auth.log (sshd/sudo syslog format)
  --rules <path>           Path to a custom rules.json (defaults to config/rules.json)
  --format <text|json>     Output format (default: text)
  -h, --help               Show this help message

Example:
  node src/index.js --webserver-log logs/webserver.log --auth-log logs/auth.log
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || (!args.webserverLogPath && !args.authLogPath)) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }

  try {
    const result = await runAnalysis({
      webserverLogPath: args.webserverLogPath && path.resolve(args.webserverLogPath),
      authLogPath: args.authLogPath && path.resolve(args.authLogPath),
      rulesConfigPath: args.rulesConfigPath && path.resolve(args.rulesConfigPath),
    });

    if (result.parseErrors.length > 0) {
      console.error(`Warning: ${result.parseErrors.length} line(s) could not be parsed and were skipped.`);
    }

    console.log(generateReport(result.incidents, args.format));

    if (args.format !== 'json') {
      console.log(`Summary: ${JSON.stringify(result.summary)}`);
    }

    // Non-zero exit if a critical incident was found — useful for CI gating.
    const hasCritical = result.incidents.some((i) => i.severity === 'critical');
    process.exit(hasCritical ? 2 : 0);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();