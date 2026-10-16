Secret Scanner
This is a Python CLI tool that scans files or foders for hardcoded secrets. It looks for things like tokens, passwords, API keys, and private keys using regex patterns.

What It Does
• Scans a file or directory
• Checks each line for secret patterns
• Shows the file name, line number, and the matched secret
• Uses argparse for the command line
• Uses logging for output messages

Patterns Included
These patterns are based on the regextokens project:

• JWT
• PEM Private Key
• GitHub Token
• AWS Access Key
• Password Assignment
