'''
please see https://cpe.mitre.org/specification/ for the CPE specification. i only
attempt to support naming specifications 2.3+

The CPE 2.3 Naming Specification defines standardized methods for assigning
names to IT product classes. An example is the following name representing
Microsoft Internet Explorer 8.0.6001 Beta:

    wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001
    ",update="beta"]

This method of naming is known as a well-formed CPE name (WFN). It is an
abstract logical construction. The CPE Naming Specification defines procedures
for binding WFNs to machine-readable encodings, as well as unbinding those
encodings back to WFNs. One of the bindings, called a Uniform Resource
Identifier (URI) binding, is included in CPE 2.3 for backward compatibility with
CPE 2.2 (see the CPE Archive). The URI binding representation of the WFN above
is:

    cpe:/a:microsoft:internet_explorer:8.0.6001:beta

The Official CPE Dictionary published and maintained by NIST contains an
authoritative enumeration of CPE names in the URI binding representation.

The second binding defined in CPE 2.3 is called a formatted string binding. It
has a somewhat different syntax than the URI binding, and it also supports
additional product attributes. With the formatted string binding, the WFN above
can be represented by the following:

    cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*

a short note about the /? as the second field. this is the "part" attribute and there
are three types of parts, {'a':'applications, 'o':'operating systems', 'h':'hardware'}

please see http://csrc.nist.gov/publications/nistir/ir7695/NISTIR-7695-CPE-Naming.pdf
for all the gory details :)

'''

__all__      = ['WFN','LOGICAL']
__version__  = '1.0'
__author__   = 'david ford <david@blue-labs.org> (also: firefighterblu3@gmail.com, rarely read)'
__copyright  = '2014 '+__author__
__license__  = 'Apache 2.0'
__released__ = '2014 August 8'


import re, string
try:
  from enum import Enum
  LOGICAL = Enum('LOGICAL', 'ANY NA')
except:
  raise Exception('You need the "enum34" package, install "enum34". Do not install "enum"')

class WFN(object):
  ''' class for binding and unbinding WFNs
  cpe:/x:x:x:x form is called a bound WFN and is referred to as a URI,
  wfn:[part="x", vendor="x", "product="x", version="x"] is an unbound WFN

  refer to NISTIR 7695 for specifications and references
  '''

  def __init__(self, *args, **kwargs):
    self.debug = False
    [setattr(self, x, None) for x in ('part','vendor','product','version','update','edition','language')]

    postproc = None
    if args and isinstance(args[0], str):
        postproc = args[0]
        args=args[1:]

    for k in args:
      if not isinstance(k, dict): raise ValueError('Please use key=value, {key:value,}, or **{key:value,}')
      if isinstance(k,dict):
        kwargs.update(k)

    # preset debug
    if 'debug' in kwargs:
      self.debug = kwargs['debug']
      del kwargs['debug']

    # initialize values
    for k,v in kwargs.items():
      if k in ['part','vendor','product','version','update','edition','language',#CPE v2.2
               'sw_edition','target_sw','target_hw','other' # CPE v2.3 extended attributes
              ]:

        # if already set, raise
        if hasattr(self, k) and getattr(self, k):
          raise KeyError('{} is already set'.format(k))

        # field validation
        if k == 'part':
          if not v in ('a','o','h'):
            raise ValueError('part can only be one of ("a","o","h")')
        # else
        # verify alphanum or escaped

        if v in ('','-'):
          v = LOGICAL.ANY

        if k == 'edition':
          if v == LOGICAL.ANY or not v[0] == '~': # unpacked value
            self._debug('bind {}={!r}'.format(k,v))
            setattr(self, k, v)
          else:                    # packed values
            self._debug('bind {}={!r}'.format(k,v))
            v = v.split('~')
            #print('v split={}'.format(v))
            for i,e in enumerate(['edition', 'sw_edition', 'target_sw', 'target_hw', 'other']):
              #print('i={}, e={}, v[i]={}'.format(i,e,v[i]))
              if v[i]:
                self._debug('bind {}={!r}'.format(e,v[i]))
                setattr(self, e, v[i])
        else:
          self._debug('bind {}={!r}'.format(k,v))
          setattr(self, k, v)

      else:
        raise KeyError('Unknown WFN field type: {}'.format(k))

    if postproc:
      self.unbind(postproc)

  def _debug(self, s):
    if self.debug:
      print(s)

  def __str__(self):
    return self.bind_to_URI()

  def __repr__(self):
    return '<WFN({})>'.format(', '.join(['{}={}'.format(k,isinstance(v,str) and '"'+v+'"' or v) for k,v in self.__dict__.items() if not k.startswith('_') and not k=='debug']))

  def _get(self, k):
    v = self.__dict__.get(k)
    #if v == LOGICAL.NA:
    #  v = '-'
    #elif v == LOGICAL.ANY:
    #  v = ''
    if v in ('',None):
      v = LOGICAL.ANY
    return v

  def _transform_for_uri(self, s):
    ''' section 6.1.2.3 '''
    result = ''

    if not s:
      return result
    #print('transforming: {!r}'.format(s))
    cgen = iter([x for x in s])
    for c in cgen:
      if c in string.ascii_letters+string.digits+'-._':
        result += c
        continue
      if c == '\\':
        c = next(cgen)
        if not c in '-.':
          c = '%'+hex(ord(c))[2:]
      elif c == '?': c = '%01'
      elif c == '*': c = '%02'
      else: c = '%'+hex(ord(c))[2:]
      result += c
    return result

  def _decode(self, s):
    if s in (None, '', LOGICAL.ANY):
      return LOGICAL.ANY

    if s == '-':
      return LOGICAL.NA

    # check for %01? or %02* in s
    # ? can occur repeatedly at the end of a string
    # * can occur once at beginning and/or end of string
    if '%01' in s or '%02' in s:
      # ?
      if re.search('(%01)+.+', s):
        raise ValueError ('? can only occur 1+ times at the end of the value')
      # *
      if re.search('.+(%02)+.+', s):
        raise ValueError ('* can only occur once at the beginning and/or end of the value')

    out = ''
    sgen = iter(s.lower())

    for c in sgen:
      if c in '.-~':
        out += '\\'+c
        continue
      if not c == '%':
        out += c
        continue

      c = next(sgen)+next(sgen)
      if c == '01':
        out += '?'
      elif c == '02':
        out += '*'
      else:
        nc = int(c, 16)
        if not nc in list(range(0x21, 0x30))+list(
                     range(0x3a,0x41))+list(
                     range(0x5b,0x5f))+[
                     0x60,0x7b,0x7c,0x7d,0x7e]:
          raise ValueError('illegal percent encoding: {}'.format(hex(nc)))
        out += '\\'+chr(nc)

    return out

  def _bind_value_for_URI(self, v):
    ''' section 6.1.2.3 '''
    # use byte strings to represent the logical values wanted by the spec
    if v == LOGICAL.ANY: return ''
    if v == LOGICAL.NA:  return '-'
    return self._transform_for_uri(v)

  def bind_to_URI(self):
    ''' section 6.1.2.3 '''
    out = []
    for k in ['part','vendor','product','version','update','edition','language',]:
      if k == 'edition':
        ed = self._bind_value_for_URI(self._get('edition'))
        v = [self._bind_value_for_URI(self._get(x))
             for x in ('sw_edition','target_sw','target_hw','other')]
        v = '~{}~{}~{}~{}'.format(*v)
        v = v != '~~~~' and '~'+ed+v or ''

      else:
        v = self._bind_value_for_URI(self._get(k))
      out.append(v)

    out = ''.join([':'+x for x in out]).strip(':')

    #if not (self.part and self.vendor and self.product and self.version):
    #  raise ValueError('missing required field data for URI "{}"'.format(out))

    return 'cpe:/'+out

  def unbind(self, URI):
    #print('unbinding: {!r}'.format(URI))
    if URI.startswith('cpe:/'):
      self.unbind_23_URI(URI[5:])
    elif URI.startswith('cpe:2.3:'):
      self.unbind_23_FS(URI[8:])
    else:
      raise ValueError('Unknown CPE format')


  def _get_comp_uri(self, uri):
    s  = ''
    pc = ''
    for c in uri:
      if c == ':' and not pc=='\\':
        yield s
        s  = ''
        pc = c
      else:
        s += c
    yield s


  def unbind_23_URI(self, URI):
    _ = self._get_comp_uri(URI)
    for k in ['part','vendor','product','version','update','edition','language']:
      try:
        v = next(_)
      except StopIteration:
        v = ''

      if not k == 'edition':
        v = self._decode(v)
        self._debug('bind {}={}'.format(k,v))
        setattr(self, k, v)
      else:
        if not v:
          setattr(self, k, LOGICAL.ANY)
          self._debug('bind {}={}'.format(k, LOGICAL.ANY))
        elif not v[0] == '~':
          v = self._decode(v)
          self._debug('bind {}={}'.format(k, v))
          setattr(self, k, v)
        else:
          #print('v be {}'.format(v))
          v=v[1:]
          for _k in ('edition','sw_edition','target_sw','target_hw'):
            _v, v = v.split('~',1)
            _v = _v and self._decode(_v) or LOGICAL.ANY

            self._debug('bind {}={}'.format(_k, _v))
            setattr(self, _k, _v)

          v = v and self._decode(v) or LOGICAL.ANY
          self._debug('bind {}={}'.format('other',v))
          setattr(self, 'other', v)

  def _get_comp_fs(self, fs):
    s  = ''
    pc = ''
    self._debug('yield from: {!r}'.format(fs))
    for c in fs:
      if c == ':' and not pc=='\\':
        yield s
        s  = ''
        pc = c
      else:
        s += c
    yield s

  def unbind_23_FS(self, FS):
    _ = self._get_comp_fs(FS)
    for k in ['part','vendor','product','version','update','edition','language',
              'sw_edition','target_sw','target_hw','other']:
      self._debug('k is {}'.format(k))
      v = next(_)
      self._debug('v is {!r}'.format(v))
      if v == '*': v = LOGICAL.ANY
      elif v == '-': v = LOGICAL.NA
      else: v = self._add_quoting(v)

      self._debug('binding {}={}'.format(k,v))
      setattr(self, k, v)


  def _add_quoting(self, s):
    # ?
    if re.search('[?]+.+', s):
      raise ValueError ('? can only occur 1+ times at the end of the value')
    # *
    if re.search('.+[*]+.+', s):
      raise ValueError ('* can only occur once at the beginning and/or end of the value')

    out=''
    cgen = iter(s)
    for c in cgen:
      if c in string.ascii_letters+string.digits+'_?*':
        out += c
        continue
      if c == '\\': # anything quoted in a bound string remains quoted
        out += c
        out += next(cgen)
        continue
      out += '\\'+c

    return out


  def _bind_value_for_fs(self, v):
    if v == LOGICAL.ANY: return '*'
    if v == LOGICAL.NA: return '-'
    return self._process_quoted_chars(v)

  def _process_quoted_chars(self, s):
    out=''
    cgen = iter(s)
    for c in cgen:
      if not c == '\\':
        out += c
      else:
        c = next(cgen)
        if c in '.-_':
          out += c
        else:
          out += '\\'+c
    return out

  def bind_to_fs(self):
    out = []
    for k in ['part','vendor','product','version','update','edition','language',
              'sw_edition','target_sw','target_hw','other']:
      out.append(self._bind_value_for_fs(self._get(k)))

    out = ''.join([':'+x for x in out]).strip(':')
    return 'cpe:2.3:'+out


if __name__ == '__main__':
  # unit testing using the examples at section 6.1.2.4
  # example 1
  foo = WFN(part="a", vendor="microsoft", product="internet_explorer", version="8\.0\.6001",
            update="beta", edition=LOGICAL.ANY)
  assert str(foo) == 'cpe:/a:microsoft:internet_explorer:8.0.6001:beta'

  # example 2
  foo = WFN(part="a", vendor="microsoft",product="internet_explorer", version="8\.*",
            update="sp?")
  assert str(foo) == 'cpe:/a:microsoft:internet_explorer:8.%02:sp%01'

  # example 3
  foo = WFN(part="a", vendor="hp", product="insight_diagnostics", version="7\.4\.0\.1570",
            update=LOGICAL.NA, sw_edition="online", target_sw="win2003", target_hw="x64")
  assert str(foo) == 'cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~'

  # example 4
  foo = WFN(part="a", vendor="hp", product="openview_network_manager",
            version="7\.51", target_sw="linux")
  assert str(foo) == 'cpe:/a:hp:openview_network_manager:7.51::~~~linux~~'

  # example 5
  foo = WFN(part="a", vendor=r"foo\\bar", product="big\$money_manager_2010",
            sw_edition="special",target_sw="ipod_touch",target_hw="80gb")
  assert str(foo) == 'cpe:/a:foo%5cbar:big%24money_manager_2010:::~~special~ipod_touch~80gb~'

  # Now unit test URI unbinding, see section 6.1.3.3
  # example 1
  foo = WFN('cpe:/a:microsoft:internet_explorer:8.0.6001:beta')
  assert (foo.part     == 'a' and
          foo.vendor   == 'microsoft' and
          foo.product  == 'internet_explorer' and
          foo.version  == '8\.0\.6001' and
          foo.update   == 'beta' and
          foo.edition  == LOGICAL.ANY and
          foo.language == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 2
  foo = WFN('cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f')
  assert (foo.part     == 'a' and
          foo.vendor   == 'microsoft' and
          foo.product  == 'internet_explorer' and
          foo.version  == '8\.\*' and
          foo.update   == 'sp\?' and
          foo.edition  == LOGICAL.ANY and
          foo.language == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 3
  foo = WFN('cpe:/a:microsoft:internet_explorer:8.%02:sp%01')
  assert (foo.part     == 'a' and
          foo.vendor   == 'microsoft' and
          foo.product  == 'internet_explorer' and
          foo.version  == '8\.*' and
          foo.update   == 'sp?' and
          foo.edition  == LOGICAL.ANY and
          foo.language == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 4
  #foo = WFN('cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~', debug=True)
  foo = WFN('cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~')
  assert (foo.part       == 'a' and
          foo.vendor     == 'hp' and
          foo.product    == 'insight_diagnostics' and
          foo.version    == '7\.4\.0\.1570' and
          foo.update     == LOGICAL.ANY and
          foo.edition    == LOGICAL.ANY and
          foo.sw_edition == 'online' and
          foo.target_sw  == 'win2003' and
          foo.target_hw  == 'x64' and
          foo.other      == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 5
  foo = WFN('cpe:/a:hp:openview_network_manager:7.51:-:~~~linux~~')
  assert (foo.part       == 'a' and
          foo.vendor     == 'hp' and
          foo.product    == 'openview_network_manager' and
          foo.version    == '7\.51' and
          foo.update     == LOGICAL.NA and
          foo.edition    == LOGICAL.ANY and
          foo.sw_edition == LOGICAL.ANY and
          foo.target_sw  == 'linux' and
          foo.target_hw  == LOGICAL.ANY and
          foo.other      == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 6
  try:
    foo = WFN('cpe:/a:foo%5cbar:big%24money_2010%07:::~~special~ipod_touch~80gb~')
    raise ValueError('WFN failed to reject invalid %07')
  except ValueError as e:
    if not str(e) == 'illegal percent encoding: 0x7':
      raise

  # example 7
  foo = WFN('cpe:/a:foo~bar:big%7emoney_2010')
  assert (foo.part       == 'a' and
          foo.vendor     == 'foo\~bar' and
          foo.product    == 'big\~money_2010' and
          foo.version    == LOGICAL.ANY and
          foo.update     == LOGICAL.ANY and
          foo.edition    == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 8
  try:
    foo = WFN('cpe:/a:foo:bar:12.%02.1234')
    print(foo)
    raise ValueError('WFN failed to reject invalid embedded %02')
  except ValueError as e:
    if not str(e) == '* can only occur once at the beginning and/or end of the value':
      raise

  # test binding WFN to a formatted string, section 6.2.2.3
  # example 1
  foo = WFN(part='a', vendor='microsoft', product='internet_explorer', version='8\.0\.6001',
            update='beta', edition=LOGICAL.ANY)
  _foo = foo.bind_to_fs()
  assert (_foo == 'cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*'
         ), 'WFN.bind_to_fs() failed to correctly assemble the Formatted String'

  # example 2
  foo = WFN(part='a', vendor='microsoft', product='internet_explorer', version='8\.\*',
            update='sp?')
  _foo = foo.bind_to_fs()
  assert (_foo == 'cpe:2.3:a:microsoft:internet_explorer:8.\\*:sp?:*:*:*:*:*:*'
         ), 'WFN.bind_to_fs() failed to correctly assemble the Formatted String'

  # example 3
  foo = WFN(part='a', vendor='hp', product='insight', version='7\.4\.0\.1570', update=LOGICAL.NA,
            sw_edition='online', target_sw='win2003', target_hw='x64')
  _foo = foo.bind_to_fs()
  assert (_foo == 'cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*'
         ), 'WFN.bind_to_fs() failed to correctly assemble the Formatted String'

  # example 4
  foo = WFN(part='a', vendor='hp', product='openview_network_manager', version='7\.51',
            target_sw='linux')
  _foo = foo.bind_to_fs()
  assert (_foo == 'cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*'
         ), 'WFN.bind_to_fs() failed to correctly assemble the Formatted String'

  # example 5
  foo = WFN(part='a', vendor='foo\\bar', product='big\$money_2010', sw_edition='special',
            target_sw='ipod_touch', target_hw='80gb')
  _foo = foo.bind_to_fs()
  assert (_foo == 'cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*'
         ), 'WFN.bind_to_fs() failed to correctly assemble the Formatted String'

  # binding WFN to a formatted string, section 6.2.3.3
  # example 1
  foo = WFN('cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*')
  assert (foo.part       == 'a' and
          foo.vendor     == 'microsoft' and
          foo.product    == 'internet_explorer' and
          foo.version    == '8\.0\.6001' and
          foo.update     == 'beta' and
          foo.edition    == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY and
          foo.sw_edition == LOGICAL.ANY and
          foo.target_sw  == LOGICAL.ANY and
          foo.target_hw  == LOGICAL.ANY and
          foo.other      == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 2
  foo = WFN('cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*')
  assert (foo.part       == 'a' and
          foo.vendor     == 'microsoft' and
          foo.product    == 'internet_explorer' and
          foo.version    == '8\.*' and
          foo.update     == 'sp?' and
          foo.edition    == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY and
          foo.sw_edition == LOGICAL.ANY and
          foo.target_sw  == LOGICAL.ANY and
          foo.target_hw  == LOGICAL.ANY and
          foo.other      == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # example 3
  foo = WFN('cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*')
  assert (foo.part       == 'a' and
          foo.vendor     == 'hp' and
          foo.product    == 'insight_diagnostics' and
          foo.version    == '7\.4\.0\.1570' and
          foo.update     == LOGICAL.NA and
          foo.edition    == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY and
          foo.sw_edition == 'online' and
          foo.target_sw  == 'win2003' and
          foo.target_hw  == 'x64' and
          foo.other      == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  # also example 3
  try:
    foo = WFN('cpe:2.3:a:hp:insight_diagnostics:7.4.*.1570:-:*:*:*:*:*:*')
    raise ValueError('WFN failed to reject invalid data')
  except ValueError as e:
    if not str(e) == '* can only occur once at the beginning and/or end of the value':
      raise

  # example 4
  foo = WFN('cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*')
  assert (foo.part       == 'a' and
          foo.vendor     == 'foo\\bar' and
          foo.product    == 'big\$money' and
          foo.version    == '2010' and
          foo.update     == LOGICAL.ANY and
          foo.edition    == LOGICAL.ANY and
          foo.language   == LOGICAL.ANY and
          foo.sw_edition == 'special' and
          foo.target_sw  == 'ipod_touch' and
          foo.target_hw  == '80gb' and
          foo.other      == LOGICAL.ANY
         ), 'WFN.unbind_URI() did not produce expected output'

  print('All section tests of NISTIR 7695 passed successfully')
