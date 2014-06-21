python-cpe-parser
=================

Parse the CPE vulnerability tree from an NVD (NIST) CVE vulnerability

given a block of HTML fetched from a CVE vulnerability page, parse the CPE vulnerability tree into a VTunit object.

todo:
  - sort CPE entries
  - remove redundant entries
  - build __lt__, __le__, __gt__, __ge__ methods for comparisons
  - build a method for testing a <= b <= c


i realize most people don't pay attention to licenses and requirements. i've no desire to harsh on people that
don't follow requirements -- but please try to. the Apache license is really permissive. basically, please retain
my copyright and disclaimer and please make attribution if you use my code. please read
http://en.wikipedia.org/wiki/Apache_License

requirements:
  python3+         (there's really not much in here that is python3 dependent, probably easy to mod for py2)
    beautifulsoup4
      lxml or similar html parser that BS4 approves of
    httplib2 - if you run this standalone. httplib2 is far more advanced than the builtin urllib/httplib combo
