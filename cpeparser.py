#!/usr/bin/env python

'''
CPE tree parser

given a block of HTML fetched from a CVE vulnerability page, parse the CPE vulnerability tree into a VTunit object.

todo:
* sort CPE entries
* remove redundant entries
* build __lt__, __le__, __gt__, __ge__ methods for comparisons
* build a method for testing a <= b <= c


i realize most people don't pay attention to licenses and requirements. i've no desire to harsh on people that
don't follow requirements -- but please try to. the Apache license is really permissive. basically, please retain
my copyright and disclaimer and please make attribution if you use my code. please read
http://en.wikipedia.org/wiki/Apache_License

requirements:
*  python3+         (there's really not much in here that is python3 dependent, probably easy to mod for py2)
  *  beautifulsoup4
    *  lxml or similar html parser that BS4 approves of
  *  httplib2 - if you run this standalone. httplib2 is far more advanced than the builtin urllib/httplib combo

'''

__all__      = ['VTtree']
__version__  = '1.3'
__author__   = 'david ford <david@blue-labs.org> (also: firefighterblu3@gmail.com, rarely read)'
__copyright  = '2015 '+__author__
__license__  = 'Apache 2.0'
__released__ = '2015 Feb 10'

import sys, os, re, time, traceback, httplib2
from bs4 import BeautifulSoup
from bs4.element import Tag, NavigableString
from pprint import pprint
from urllib.parse import urlencode

# borrowed from gentoo portage
_v   = r'(cvs\.)?(\d+)((\.\d+)*)([a-z]?)((_(pre|p|beta|alpha|rc)\d*)*)'
_rev = r'\d+'
_vr  = '^(?P<ver>' + _v + ')(-r(?P<rev>' + _rev + '))?$'

ver_re = re.compile(_vr)


class VTunit(object):
    '''Method properties:
    name   - set to one of three things; ['Configuration \d+', 'AND', 'OR']
    parent - the parent node of this subtree

    Additional properties are 'sub' and 'cpe' and are established as needed
    Properties of 'cpe' are: {'vulnerable', 'cpe', 'previous', 'future'}

    If there is an '*' prefixing a CPE entry on the NVD website, that means the listed version is vulnerable.

    If "and previous versions" suffixes the CPE tree, this indicates that all versions older than this version
    are vulnerable|not vulnerable (per '*' flag)

    Same for "and future versions" (text may change when I encounter such a beastie)
    '''
    def __init__(self, name=None, parent=None):
        self.name   = name
        self.parent = parent

    def __contains__(self, k):
        if k in self.__dict__:
            return True

    def descend(self, name):
        ''' create a descendent; append it to our sub list, then set its parent to ourself
        '''
        sub = VTunit(name=name, parent=self)
        if not 'sub' in self: self.sub = []
        self.sub.append(sub)
        return sub

    def __str__(self):
        ''' Parses itself for printing, recursively descending and printing the whole tree in logical order.
        '''
        __indent=0
        __p = self.parent
        while __p:
            __indent += 2
            __p = __p.parent

        __s=[]

        __s.append('{}{}'.format(' '*__indent, self.name))

        if 'sub' in self:
            for sub in self.sub:
                __s.append(str(sub))
        elif 'cpe' in self:
            for __cpe in self.cpe:
                __vn = ('vulnerable' in __cpe and __cpe['vulnerable']) and '*'  or ' '
                __pv = ('previous'   in __cpe and __cpe['previous'])   and '<=' or '  '
                __c = __cpe['cpe']
                __s.append('  {}{}{}{}'.format(' '*__indent,__pv,__c,__vn))

        return '\n'.join(__s)

    def sort(self):
        ''' sort my list of cpe entries
            ** NOT FUNCTIONAL YET **
        '''
        if not 'cpe' in self:
            return

        for __cpe in self.cpe:
            pass


class VTtree():
    def __init__(self, vid=None):
        self.vid = vid
        pass

    def __contains__(self, k):
        pass

    def __lt__(self, k):
        pass

    def __le__(self, k):
        pass

    def __gt__(self, k):
        pass

    def __ge__(self, k):
        pass

    def parse(self, content):
        ''' Find configuration trees. These are NOT ordered by heirarchy in the HTML, they are linear. Additionally, NVD
        folks use javascript to rewrite tables with enclosing divs. so in the browser, instead of 52 sibling tables,
        you'll see 8 tables with intermixed divs (ref: CVE-2014-0532)

        Input:
          content - chunk of HTMl to parse

        Returns:
          nothing, appends a VTunit() class representing parsed tree to self

        '''

        if not content:
            return

        self.tree = VTunit()
        self.tree.name = 'Top'
        
        soup = BeautifulSoup(content, 'lxml').body
        soup = soup.find('div', id=
            'BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter'+
            '_VulnerabilityDetail_VulnFormView_VulnConfigurationsDiv')

        e_list = soup.find_all(text=re.compile('(Configuration \d+|AND|OR|\*|cpe:)'))
        self.e_list_i = iter(e_list)

        # start the show
        self._descend_tree(next(self.e_list_i), self.tree)


    def print(self):
        print(self.tree)
    

    def _iter_nodes(self, node):
        yield node
        if 'sub' in node:
            for _node in node.sub:
                for __ in self._iter_nodes(_node):
                    yield __
    
    
    def get_vulnerable_software_names(self):
        _list = []
        _bad_cpes = []
        for node in self._iter_nodes(self.tree):
            if 'cpe' in node:
                for __cpe in node.cpe:
                    if 'vulnerable' in __cpe:
                        http = httplib2.Http()
                        
                        # this URL is semi private and subject to change at any time
                        # please contact <david@blue-labs.org> if you need access to a
                        # cpe to title mapping database
                        # cpename should be in the form of:  'cpe:/a:adobe:flash_player:11.2.202.251'
                        # and you'll get a response of:      'Adobe Flash Player'
                        cpename = __cpe['cpe']
                        resp,content = http.request('https://api.security-carpet.com:1443/cpe_to_title',
                                                    'POST',
                                                    urlencode({'cpe':cpename}),
                                                    headers={'Content-Type':'text/plain'},
                                                    )

                        if not resp['status'] == '200':
                            if not resp['status'] == '404':
                                print('problem fetching cpe title, response follows:')
                                pprint(resp)
                                print('{!r}'.format(content))
                            _bad_cpes.append(__cpe['cpe'])
                        else:
                            _list.append(content.decode())


        # command line fixups
        title = 'eh?'
        if len(sys.argv) > 2:
            title = sys.argv[2]

        _bad_cpes.sort()
        for _ in _bad_cpes:
          print("insert into cpe_names values ('{}','en-US','{}');".format(_,title))
        for _ in _bad_cpes:
          print("        ('{}','en-US','{}'),".format(_,title))

        return sorted(set(_list))


    def _descend_tree(self, e, tree_node):
        cpes_started = False
        cpe={}

        while e:
            _ = e.string.strip()
            if _.startswith('+ '):
                _ = _[2:]

            if 'cpe' in tree_node and not _[0] in ('*','c','a'):
                tree_node.cpe.append(cpe)
                return e

            elif _.startswith('Configuration'):
                # data from last pass? store it
                if cpe:
                    if not 'cpe' in tree_node: tree_node.cpe = []
                    tree_node.cpe.append(cpe)
                cpe={}

                # return to the Top unit
                while tree_node.parent: tree_node = tree_node.parent

                e = self._descend_tree(next(self.e_list_i), tree_node.descend(_))
                continue

            elif _ in ('AND','OR'):
                # data from last pass? store it
                if cpe:
                    if not 'cpe' in tree_node: tree_node.cpe = []
                    tree_node.cpe.append(cpe)
                cpe = {}

                e = self._descend_tree(next(self.e_list_i), tree_node.descend(_))
                continue

            # brand new cpe line found
            elif _ == '*':
                # data from last pass? store it
                if cpe:
                    if not 'cpe' in tree_node: tree_node.cpe = []
                    tree_node.cpe.append(cpe)

                cpe = {'vulnerable':True}

            elif _.startswith('cpe:'):
                if not 'cpe' in tree_node: tree_node.cpe = []

                # concat version suffix using '_' for our gentoo based version sorting
                try:
                    _v = _.split(':',5)

                    if   len(_v) == 5:  _v=_v[4]
                    elif len(_v) == 6:  _v=_v[4] +'_'+ _v[5]

                    __ = ver_re.match(_v)
                except Exception as exc:
                    pass

                # if an existing cpe:... exists in the dictionary, push it and start fresh
                if cpe and 'cpe' in cpe:
                    tree_node.cpe.append(cpe)
                    cpe = {}

                # fixups, sigh. expect many more to come. CVE web pages don't match CPE dictionary.
                # p.p.s. expect this to vanish, I'll just duplicate the CPE entries
                if _.startswith('cpe:/a:larry_wall:perl:'):
                    _ = _.replace('cpe:/a:larry_wall:perl:', 'cpe:/a:perl:perl:')
                cpe['cpe'] = _

                # soup doesn't find sibling post-pended text in a wrongly built tag.
                # for example: <a>foo<a>bar</a>bum</a>, so we navigate to it ourselves

                suffixtext = [x for x in e.parent.children if isinstance(x,NavigableString)]
                if suffixtext and suffixtext[-1] == ' and previous versions':
                    cpe['previous'] = True

                # does this type of rule exist?
                if suffixtext and suffixtext[-1] == ' and future versions':
                    cpe['future'] = True

                # fixups
                if self.vid:
                    if self.vid == 'CVE-2004-1296' and cpe['cpe'] == 'cpe:/a:gnu:groff:1.18.1':
                        cpe['vulnerable'] = True
                    if self.vid == 'CVE-2006-7247' and cpe['cpe'] == 'cpe:/a:mambo-foundation:mambo:-':
                        cpe['vulnerable'] = True
                

                pfx = ('vulnerable' in cpe and cpe['vulnerable']) and '* ' or ''
                pvv = ('previous' in cpe and cpe['previous']) and '<= ' or ''
                
                #print('{}{}{} added to {}'.format(pfx,pvv,_,v.name))
            
            elif _ == '* Denotes Vulnerable Software': # ignore this line
                pass

            else:
                raise Exception('unexpected content encountered: {}'.format(_))

            try:
                e=next(self.e_list_i)
            except:
                if cpe: tree_node.cpe.append(cpe)
                break




def main():
    import httplib2
    
    if len(sys.argv) >1:
        vid = sys.argv[1]
    else:
        vid='CVE-2009-4307'

    # make sure your user has r/w access to this cache directory, or omit it
    http = httplib2.Http('/var/cache/vd-feeds')

    print('Fetching CVE detail page for {}'.format(vid))
    
    # hardwired to skip the cache, WEB.NVD.NIST.GOV can be damned slow even for HEAD requests
    if True and os.path.exists('/tmp/{}.html'.format(vid)):
      with open('/tmp/{}.html'.format(vid), 'rb') as f:
         content = f.read()

    else:
      try:
        response, content = http.request('http://web.nvd.nist.gov/view/vuln/detail?vulnId={}'.format(vid))
        with open('/tmp/{}.html'.format(vid), 'wb') as f:
          f.write(content)
      except:
        t,v,tb = sys.exc_info()
        print('Could not fetch http://web.nvd.nist.gov/view/vuln/detail?vulnId={}: {}'.format(vid, v))
        return

    VT = VTtree(vid)
    VT.parse(content)
    VT.print()
    print(VT.get_vulnerable_software_names())
    

if __name__ == '__main__':
    main()
