# wafme
ModSecurity rule editor and log analysis

The WAFme component is intended for tailing live audit logs and generate the rules and exceptions to prevent ModSecurity from blocking the regular website/webapp usability.

- /!\ This assumes that the log is free of attacks and malicious payloads.

Tuning the CRS usually will require:
- R1) identify element triggering the rules
- R2) check that the payload in such element is normal not malicious
- R3) evaluate the scope where such element is present
- R4) whitelist such element for the specific rule id within the least possible scope
- R5) update the ruleset to add the exceptions 
- R6) add rules to check the whitelisted element contains the expected values
- R7) reload the configuration

Some of the different scopes can be defined as:
- A1) Match of URI + element + payload type validation (regex, type, length, values)
- A2) Match URI + element
- A3) Match element for all URI + payload type validation (regex, type, length, values)
- A4) Match element for all URI
- A5) Match URI
- A6) VHost
- A7) Server

At this moment WAFme will check R1, R3, R4, R5, R7 and try to limit the element whitelisting to A2 and if the threshold is exceeded will use A4.

# Usage
- Install WAFme
```
git clone https://github.com/spartantri/wafme.git
cd wafme
ln -s /var/log/apache2/modsec_audit.log audit.log
```

- Configure the OUTPUT_FILE, audit.log location, exceptions and other global variables and webserver restart script
- Navigate the web site, use an automated test suite if available and press CTRL+C to generate the ruleset and reload, the output to screen will include a requests python command that can be used to reproduce the exact same request, this is useful as in many cases the ruleset generation is aprocess that would require many iterations as once a rule blocks the request other elements and rules may not be processed yet.
- Test the navigation again until no denied requests are present and the website navigation is flawless

TIPS:
To speed up the process:
- start with low Paranoia levels
- use "SecRuleEngine DetectionOnly" during the first web site navigation test to get the most rules without blocking the request
- use "SecRuleEngine On" once the ruleset generated is stable to reduce the number of iterations
- use an automated test suite to check all functionalities, use modsec-replay (https://github.com/spartantri/modsec-replay)

TODO:
- resend blocked requests and identify further false positives
- positive checks on whitelisted elements
- increase logging capabilities
- check for rule functional duplicates/redundancies
- save rule set to XML for compatibility with WebAppProfiler and jwall
- support paranoia levels
