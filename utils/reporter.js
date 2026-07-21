const mocha = require('mocha');
const { EVENT_RUN_END, EVENT_TEST_FAIL, EVENT_TEST_PASS } = mocha.Runner.constants;

class CustomReporter extends mocha.reporters.Base {
    constructor(runner) {
        super(runner);
        let passes = 0;
        let failures = 0;

        runner.on(EVENT_TEST_PASS, () => { passes++; });
        runner.on(EVENT_TEST_FAIL, () => { failures++; });

        runner.once(EVENT_RUN_END, () => {
            console.log('\n========================================');
            console.log('       TEST EXECUTION REPORT            ');
            console.log('========================================');
            console.log(` TOTAL PASSED TESTS : ${passes}`);
            console.log(` TOTAL FAILED TESTS : ${failures}`);
            console.log(` TOTAL TESTS RUN    : ${passes + failures}`);
            console.log('========================================\n');
        });
    }
}

module.exports = CustomReporter;