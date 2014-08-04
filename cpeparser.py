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
__version__  = '1.0'
__author__   = 'david ford <david@blue-labs.org> (also: firefighterblu3@gmail.com, rarely read)'
__copyright  = '2014 '+__author__
__license__  = 'Apache 2.0'
__released__ = '2014 June 21'

import sys, re, time, traceback
from bs4 import BeautifulSoup
from bs4.element import Tag, NavigableString
from pprint import pprint

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
    

class VTtree():
    def __init__(self):
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
          VTunit() class representing parsed tree

        '''
    
        if not content:
            return
    
        self.tree = VTunit()
        self.tree.name = 'Top'

        soup = BeautifulSoup(content, 'lxml').body.find('div', id=
            'BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_VulnSoftwareTreeView')

        e_list = soup.find_all('a', text=re.compile('(Configuration \d+|AND|OR|\*|cpe:)'))
        self.e_list_i = iter(e_list)

        # start the show
        self._descend_tree(next(self.e_list_i), self.tree)

    
    def print(self):
        print(self.tree)


    def _descend_tree(self, e, tree_node):
        cpes_started = False
        cpe={}

        while e:
            _ = e.string.strip()

            if 'cpe' in tree_node and not _[0] in ('*','c','a'):
                tree_node.cpe.append(cpe)
                return e
            
            elif _.startswith('Configuration'):
                if cpe:
                    if not 'cpe' in tree_node: tree_node.cpe = []
                    tree_node.cpe.append(cpe)
                cpe={}

                # return to the Top unit
                while tree_node.parent: tree_node = tree_node.parent

                e = self._descend_tree(next(self.e_list_i), tree_node.descend(_))
                continue

            elif _ in ('AND','OR'):
                if cpe:
                    if not 'cpe' in tree_node: tree_node.cpe = []
                    tree_node.cpe.append(cpe)
                cpe = {}

                e = self._descend_tree(next(self.e_list_i), tree_node.descend(_))
                continue

            # brand new cpe line found
            elif _ == '*':
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
                
                cpe['cpe'] = _
                
                # soup doesn't find sibling post-pended text in a wrongly built tag.
                # for example: <a>foo<a>bar</a>bum</a>, so we navigate to it ourselves

                suffixtext = [x for x in e.parent.children if isinstance(x,NavigableString)]
                if suffixtext and suffixtext[-1] == ' and previous versions':
                    cpe['previous'] = True
                
                # does this type of rule exist?
                if suffixtext and suffixtext[-1] == ' and future versions':
                    cpe['future'] = True
                
                pfx = ('vulnerable' in cpe and cpe['vulnerable']) and '* ' or ''
                pvv = ('previous' in cpe and cpe['previous']) and '<= ' or ''

                #print('{}{}{} added to {}'.format(pfx,pvv,_,v.name))
            
            else:
                raise Exception('unexpected content encountered: {}'.format(_))

            try:
                e=next(self.e_list_i)
            except:
                if cpe: tree_node.cpe.append(cpe)
                break



def main():
    import httplib2

    # make sure your user has r/w access to this cache directory, or omit it
    http = httplib2.Http('/var/cache/vd-feeds')
    
    print('Fetching CVE detail page for CVE-2014-0532')
    
    try:
        response, content = http.request('http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0532')
    except:
        t,v,tb = sys.exc_info()
        print('Could not fetch http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0532: {}'.format(v))
        return

    VT = VTtree()
    VT.parse(content)
    VT.print()


if __name__ == '__main__':
    main()
