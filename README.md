python-cpe-parser
=================

Parse the CPE vulnerability tree from an NVD (NIST) CVE vulnerability

Given a block of HTML fetched from a CVE vulnerability page, parse the CPE vulnerability tree into a VTunit object.

Todo:
* sort CPE entries
* remove redundant entries
* build `__lt__, __le__, __gt__, __ge__` methods for comparisons
* build a method for testing `a <= b <= c`


I realize most people don't pay attention to licenses and requirements. i've no desire to harsh on people that
don't follow requirements -- but please try to. the Apache license is really permissive. basically, please retain
my copyright and disclaimer and please make attribution if you use my code. please read
http://en.wikipedia.org/wiki/Apache_License

disclaimer: no dragons were harmed in the making of this module. regardless if you rolled a 20 on your d20, it's a
game. i'll try to help with problems but your expectations of liability are limited to what you paid me.

Requirements:
* python3+         (there's really not much in here that is python3 dependent, probably easy to mod for py2)
  *  beautifulsoup4
    * lxml or similar html parser that BS4 approves of
  *  httplib2 - if you run this standalone. httplib2 is far more advanced than the builtin urllib/httplib combo


Example built into the module is CVE-2014-0532:

```
david@scott ~ $ python cpe_parser.py
Fetching CVE detail page for CVE-2014-0532
Top
  Configuration 1
    OR
      <=cpe:/a:adobe:adobe_air:13.0.0.111*
        cpe:/a:adobe:adobe_air:13.0.0.83*
  Configuration 2
    AND
      OR
          cpe:/a:adobe:flash_player:11.2.202.356
          cpe:/a:adobe:flash_player:11.2.202.350
          cpe:/a:adobe:flash_player:11.2.202.346
          cpe:/a:adobe:flash_player:11.2.202.341
          cpe:/a:adobe:flash_player:11.2.202.336
          cpe:/a:adobe:flash_player:11.2.202.335
          cpe:/a:adobe:flash_player:11.2.202.332
          cpe:/a:adobe:flash_player:11.2.202.310
          cpe:/a:adobe:flash_player:11.2.202.297
          cpe:/a:adobe:flash_player:11.2.202.291
          cpe:/a:adobe:flash_player:11.2.202.285
          cpe:/a:adobe:flash_player:11.2.202.280
          cpe:/a:adobe:flash_player:11.2.202.275
          cpe:/a:adobe:flash_player:11.2.202.273
          cpe:/a:adobe:flash_player:11.2.202.270
          cpe:/a:adobe:flash_player:11.2.202.262
          cpe:/a:adobe:flash_player:11.2.202.261
          cpe:/a:adobe:flash_player:11.2.202.258
          cpe:/a:adobe:flash_player:11.2.202.251
          cpe:/a:adobe:flash_player:11.2.202.243
          cpe:/a:adobe:flash_player:11.2.202.238
          cpe:/a:adobe:flash_player:11.2.202.236
          cpe:/a:adobe:flash_player:11.2.202.235
          cpe:/a:adobe:flash_player:11.2.202.233
          cpe:/a:adobe:flash_player:11.2.202.228
          cpe:/a:adobe:flash_player:11.2.202.223
        <=cpe:/a:adobe:flash_player:11.2.202.359*
      OR
          cpe:/o:linux:linux_kernel
  Configuration 3
    AND
      OR
          cpe:/a:adobe:flash_player:13.0.0.182*
          cpe:/a:adobe:flash_player:13.0.0.201*
          cpe:/a:adobe:flash_player:13.0.0.206*
        <=cpe:/a:adobe:flash_player:13.0.0.214*
      OR
          cpe:/o:apple:mac_os_x
          cpe:/o:microsoft:windows
  Configuration 4
    OR
      <=cpe:/a:adobe:adobe_air_sdk:13.0.0.111*
        cpe:/a:adobe:adobe_air_sdk:13.0.0.83*
```
