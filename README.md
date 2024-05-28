# TerminalChecker

It is a simple code used to check malicious files or URLs, usable via terminal.
The code was entirely written in Python, in addition to using the Total Virus API to know whether your file/url is malicious or not.
The code is still in its first version! I ask that if you see possible improvements or errors, please contact me so that I can improve and correct them. Thank you very much in advance!

<h2>How to Install?</h2>
In terminal, use:
  "git clone https://github.com/Gustavounic/TerminalChecker.git"

Then, install the requirements.txt, with this command:
  "pip install -r requirements.txt"

<h2>How to Use?</h2>
First, go to file "config.ini" and input your API KEY from VirusTotal account

Now, in terminal:
-u or --url for URL
or 
-f or --file for File(path)

Syntax:
  python -f [path_file]
  or
  python -u [url]


<h3>The answers are very simple, but they tell you based on API scanners if your file/URL contains some kind of malware or not, I will try to improve them soon to provide more information, but thanks for trying and I hope you like it!</h3>

