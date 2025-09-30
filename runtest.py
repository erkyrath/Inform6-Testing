#!/usr/bin/env python3

# This script runs the Inform 6 compiler many times, testing for memory
# overflow conditions. It uses the I6 source files in the src directory.
# It also assumes that there's a usable Inform binary in the current
# directory. (If not, supply a --binary argument.)
#
# To run: "python runtest.py".
#
# You can also specify "python runtest.py FOO" to run only the named test
# group, or "python runtest.py Advent.inf" or "python runtest.py dict*"
# to run only tests with the named source file(s).
#
# This currently works on MacOSX only. It uses the "libgmalloc" debugging
# library available on OSX. (Type "man libgmalloc".) It could be adapted
# to other debugging-malloc libraries, but you'd have to adjust the
# magic environment variables, and maybe the stderr parsing.
#
# Memory settings not yet tested:
#
# DICT_WORD_SIZE
# DICT_CHAR_SIZE (glulx)
# HASH_TAB_SIZE
# MAX_LINK_DATA_SIZE
# MAX_TRANSCRIPT_SIZE

# Settings that don't result in compiler memory allocations, so they don't
# need to be tested here:
#
# MEMORY_MAP_EXTENSION
# MAX_STACK_SIZE

import sys
import os
import re
import fnmatch
import hashlib
import signal
import subprocess
import optparse

popt = optparse.OptionParser(usage='runtest.py [options] [tests...]')

popt.add_option('-b', '--binary',
    action='store', dest='binary', default='./inform',
    help='path to Inform binary (default: ./inform)')
popt.add_option('--reg',
    action='store_true', dest='runreg',
    help='run the compiled games using regtest (where supplied)')
popt.add_option('--regtest',
    action='store', dest='regtest', default='./regtest',
    help='path to regtest script (default: ./regtest)')
popt.add_option('--nolibgmalloc',
    action='store_false', dest='libgmalloc', default=True,
    help='skip using the libgmalloc library')
popt.add_option('--underflow',
    action='store_true', dest='underflow',
    help='guard against array underflow (rather than overflow)')
popt.add_option('--alignment',
    action='store', type=int, dest='alignment', default=1,
    help='align allocation on N-byte boundaries (must be 1, 4, or 16; default is 1)')
popt.add_option('--stdout',
    action='store_true', dest='stdout',
    help='display stdout for every compile')
popt.add_option('--stderr',
    action='store_true', dest='stderr',
    help='display stderr for every compile')
popt.add_option('--checksum',
    action='store_true', dest='checksum',
    help='display checksum for every compile')
popt.add_option('-l', '--list',
    action='store_true', dest='listtests',
    help='display list of tests')
popt.add_option('--vital',
    action='store_true', dest='vital',
    help='abort all tests on the first error')

(opts, args) = popt.parse_args()

testname = '???'
testlist = []
errorlist = []
md5map = {}  # maps match-keys to md5 checksums

def compile(srcfile, destfile=None,
            glulx=False, zversion=None, versiondirective=False,
            includedir=None, moduledir=None,
            memsettings={}, define={}, trace={},
            debug=False, strict=True, infix=False,
            economy=False, makeabbrevs=False,
            debugfile=False,
            bigmem=False,
            makemodule=False, usemodules=False):
    """Perform one Inform compile, and return a Result object.

    By default, this compiles to the Inform default target (z5). You
    can pass zversion=N or Glulx=True to build a different target.
    If the source file has Includes, supply the include path as includedir.
    The memsettings (now a misnomer) can include any "$FOO=..." compiler
    setting.
    The define map defines numeric constants for the source.
    
    Other switches:
    - debug turns on DEBUG mode (-D)
    - strict=False turns off STRICT mode (-~S)
    - infix turns on INFIX mode (-X)
    - economy turns on economy (abbreviation) mode (-e)
    - makeabbrevs generates abbreviations (-u)
    - debugfile generates gameinfo.dbg (-k)
    - bigmem turns on large-memory (odd-even) mode for V6/7 (-B)
    - makemodule generates a .m5 link module (-M)
    - usemodules uses modules for verblibm/parserm (-U)
    - versiondirective indicates that the source file has a "Version"
        directive, so the compiler does not need the -vN switch
    """
    argls = [ opts.binary ]
    if includedir:
        argls.append('+include_path='+includedir)
    if moduledir:
        argls.append('+module_path='+moduledir)
    argls.append('+code_path=build')
    argls.append('-E0')

    # Arguments which will be displayed in the results.
    showargs = []
    
    if glulx:
        showargs.append('-G')
    elif zversion and not versiondirective:
        showargs.append('-v%d' % (zversion,))
    for (key, val) in list(memsettings.items()):
        showargs.append('$%s=%s' % (key, val))
    for (key, val) in list(define.items()):
        if val is None:
            showargs.append('$#%s' % (key,))
        else:
            showargs.append('$#%s=%d' % (key, val))
    for (key, val) in list(trace.items()):
        showargs.append('$!%s=%s' % (key, val,))
    if debug:
        showargs.append('-D')
    if not strict:
        showargs.append('-~S')
    if infix:
        showargs.append('-X')
    if economy:
        showargs.append('-e')
    if makeabbrevs:
        showargs.append('-u')
    if debugfile:
        showargs.append('-k')
        showargs.append('+debugging_name=build/gameinfo.dbg')
    if bigmem:
        showargs.append('-B')
    if makemodule:
        showargs.append('-M')
    if usemodules:
        showargs.append('-U')
        
    argls.extend(showargs)

    # Final arguments.
    argls.append('-w')
    argls.append(os.path.join('src', srcfile))

    # Quote some arguments for display purposes only.
    printargls = [ "'"+val+"'" if '$' in val else val for val in argls ]
    print('Running:', ' '.join(printargls))

    env = dict(os.environ)
    
    if opts.libgmalloc:
        env['DYLD_INSERT_LIBRARIES'] = '/usr/lib/libgmalloc.dylib'
    
        if opts.alignment == 4:
            env['MALLOC_WORD_SIZE'] = '1'
        elif opts.alignment == 16:
            env['MALLOC_VECTOR_SIZE'] = '1'
        else:
            env['MALLOC_STRICT_SIZE'] = '1'
            
        if (opts.underflow):
            env['MALLOC_PROTECT_BEFORE'] = '1'
    
    run = subprocess.Popen(argls, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = run.communicate()
    
    try:
        stdout = stdout.decode()
    except UnicodeDecodeError:
        # Fallback in case of bad output
        stdout = stdout.decode('latin-1')
    try:
        stderr = stderr.decode()
    except UnicodeDecodeError:
        # Fallback in case of bad output
        stderr = stderr.decode('latin-1')
        
    res = Result(run.returncode, stdout, stderr, srcfile=srcfile, destfile=destfile, args=showargs, zversion=zversion, glulx=glulx, makemodule=makemodule)

    print('...%s' % (res,))
    if (opts.stdout):
        print('--- stdout:')
        print(stdout)
        print('---')
    if (opts.stderr):
        print('--- stderr:')
        print(stderr)
        print('---')
    return res

class Result:
    """Result: Represents the result of an Inform compile.

    The compile() function constructs one of these. The constructor will
    note an error if there's anything blatantly wrong (like a segfault).
    Then the test function can call is_ok() or is_memsetting() to check
    that the result is as expected.
    """
    
    SIGNAL = 'signal'
    OK = 'ok'
    ERROR = 'error'
    
    def __init__(self, retcode, stdout, stderr, srcfile=None, destfile=None, args=[], zversion=None, glulx=False, makemodule=False):
        self.srcfile = srcfile
        self.args = args
        self.glulx = glulx
        self.zversion = zversion
        self.status = None
        self.filename = None
        self.signame = None
        self.warnings = 0
        self.errors = 0
        self.memsetting = None
        self.abbreviations = []

        if destfile is not None:
            self.filename = os.path.join('build', destfile)
        elif srcfile is not None:
            val, _, suffix = srcfile.rpartition('.')
            if suffix != 'inf':
                raise Exception('srcfile is not a .inf file')
            suffix = ''
            if not glulx:
                if not makemodule:
                    suffix = '.z'
                else:
                    suffix = '.m'
                if zversion:
                    suffix += '%d' % (zversion,)
                else:
                    suffix += '5'
            else:
                suffix = '.ulx'
            self.filename = os.path.join('build', val+suffix)
        
        if (retcode < 0):
            signame = 'SIG???'
            for key in dir(signal):
                if (key.startswith('SIG') and getattr(signal, key) == -retcode):
                    signame = key
                    break
            self.status = Result.SIGNAL
            self.signame = signame
            note_error(self, 'Run ended with signal %s' % (signame,))
        else:
            lines = stderr.split('\n')
            for ln in lines:
                inheader = True
                if ('GuardMalloc[' in ln):
                    if (inheader):
                        if re.match('GuardMalloc[^:]*: version [0-9.]*', ln):
                            inheader = False
                        continue
                    note_error(self, 'Apparent libgmalloc error ' + ln)
            
            lines = stdout.split('\n')
            outlines = 0
            for ln in lines:

                match = re.match(r'Abbreviate "([^"]*)";', ln)
                if match:
                    self.abbreviations.append(match.group(1))
                    continue
                
                match = re.match(r'(?:"[^"]*", )?line (\d+)(?:[:] [(]"[^"]*"[)])?: Error:', ln)
                if (match):
                    # Errors are counted from the "Compiled" line, not here
                    # Check for a recognized error
                    err = ln[ match.end() : ].strip()
                    if err.startswith('Too many local variables for a routine'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_LOCAL_VARIABLES'
                    if err.startswith('All 233 global variables'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_GLOBAL_VARIABLES'
                    if err.startswith('Only dynamic strings @'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_DYNAMIC_STRINGS'
                    if err.startswith('The number of abbreviations has exceeded'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_ABBREVS'
                    if err.startswith('Abbreviation too long'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_ABBREV_LENGTH'
                    if err.startswith('Name exceeds the maximum length'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_IDENTIFIER_LENGTH'
                    if err.startswith('An additive property has inherited so many values') or re.match('^Limit [(]of [0-9]+ values[)] exceeded for property', err):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_PROP_LENGTH_ZCODE'
                    if re.match('^All [0-9]+ properties already declared', err):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_COMMON_PROPS'
                    if re.match('^All[0-9 ]*attributes already declared', err):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_ATTRIBUTES'
                    if err.startswith('\'If\' directives nested too deeply'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_IFDEF_STACK'
                    if err.startswith('At most 32 values can be given in a single \'switch\' case'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_SPEC_STACK'
                    if err.startswith('Short name of object'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_SHORT_NAME_LENGTH'
                    if err.startswith('Grammar version 1 cannot support more than 255 prepositions'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_PREPOSITIONS_GV1'
                    if err.startswith('Z-code is limited to 255 verbs'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_VERBS_ZCODE'
                    if err.startswith('Verb word is too long'):
                        if self.memsetting is None:
                            self.memsetting = 'MAX_VERB_WORD_SIZE'
                    continue

                match = re.match(r'.*.Compiler errors. should never occur.*', ln)
                if (match):
                    note_error(self, 'Compiler error')
                    continue
                
                match = re.match(r'(?:"[^"]*", )?line (\d+)(?:[:] [(]"[^"]*"[)])?: Fatal error:', ln)
                if (match):
                    outlines += 1
                    self.errors = 1
                    if 'Too many errors' in ln:
                        # not really 9999, but it gets the idea across
                        self.errors = 9999
                    ln = ln[ match.end() : ].strip()
                    match = re.match(r'The memory setting (\S+)', ln)
                    if (match):
                        # This no longer occurs in Inform. We keep the check for testing older releases.
                        self.memsetting = match.group(1)
                    continue
                
                match = re.match(r'Compiled with (\d+) errors? and (\d+) suppressed warnings?(?: \(no output\))?', ln)
                if (match):
                    outlines += 1
                    self.errors = int(match.group(1))
                    self.warnings = int(match.group(2))
                    continue

                match = re.match(r'Compiled with (\d+) errors?(?: \(no output\))?', ln)
                if (match):
                    outlines += 1
                    self.errors = int(match.group(1))
                    continue
                
                match = re.match(r'Compiled with (\d+) suppressed warnings?', ln)
                if (match):
                    outlines += 1
                    self.warnings = int(match.group(1))
                    continue
                
                match = re.match('Compiled', ln)
                if (match):
                    note_error(self, 'Unmatched "Compiled" line in output: ' + ln)
                    continue

            if (outlines > 1):
                note_error(self, 'Too many "Compiled" lines in output')

            if (retcode == 0):
                self.status = Result.OK
                if (self.errors):
                    note_error(self, 'Run status zero despite %d errors' % (self.errors,))
            else:
                self.status = Result.ERROR
                if (not self.errors):
                    note_error(self, 'Run status nonzero despite no errors')

    def __str__(self):
        if (self.status == Result.SIGNAL):
            return '<Signal ' + self.signame + '>'
        if (self.status == Result.OK):
            res = '<Ok'
        else:
            res = '<Error'
        if (self.errors):
            res = res + ' (%d error%s)' % (self.errors, ('' if self.errors==1 else 's'),)
        if (self.warnings):
            res = res + ' (%d warning%s)' % (self.warnings, ('' if self.warnings==1 else 's'),)
        if (self.memsetting):
            res = res + ' (%s failed)' % (self.memsetting,)
        return res + '>'

    def canonical_debugfile_checksum(self, filename):
        """ Load a gameinfo file and construct an MD5 checksum, allowing for
        differences in compiler version.
        """
        infl = open(filename, 'rb')
        dat = infl.read()
        infl.close()

        pat = re.compile(b'content-creator-version="[0-9.]+"')
        dat = pat.sub(b'content-creator-version="..."', dat)
        pat = re.compile(b'<story-file-prefix>[a-zA-Z0-9+/=]*</story-file-prefix>')
        dat = pat.sub(b'<story-file-prefix/>', dat)
        
        return hashlib.md5(dat).hexdigest()
    
    def canonical_checksum(self):
        """ Load a game file and construct an MD5 checksum, allowing for
        differences in serial number and compiler version.
        """
        infl = open(self.filename, 'rb')
        dat = infl.read()
        infl.close()
        dat = bytearray(dat)
        
        if not self.glulx:
            if len(dat) < 64:
                raise Exception('Not a valid Z-code file')
            # Serial number
            dat[18:24] = b'\0\0\0\0\0\0'
            # Checksum
            dat[28:30] = b'\0\0'
            # Compiler version number (not part of the Z-spec, but always produced by Inform 6)
            dat[60:64] = b'\0\0\0\0'
        else:
            if len(dat) < 64:
                raise Exception('Not a valid Glulx file')
            # Checksum
            dat[32:36] = b'\0\0\0\0'
            # Compiler version number
            dat[44:48] = b'\0\0\0\0'
            # Serial number
            dat[54:60] = b'\0\0\0\0\0\0'

        return hashlib.md5(dat).hexdigest()

    def is_ok(self, md5=None, md5match=None, reg=None, abbreviations=None, debugfile=None, warnings=None):
        """ Assert that the compile was successful.
        If the md5 argument is passed, we check that the resulting binary
        matches.
        If the abbreviations argument passed, we check that the compile
        produced those abbreviations. (Not necessarily in the same order.)
        If the warnings argument is passed, we check that exactly that
        many warnings were generated.
        If the reg argument is passed, we run the specified regression
        test(s) and make sure *they* pass. (May be a string or list of
        strings.)
        If the debugfile argument is passed, we check that the gameinfo.gdb
        file matches (the md5 checksum).
        """
        if (self.status == Result.OK):
            if not os.path.exists(self.filename):
                note_error(self, 'Game file does not exist: %s' % (self.filename,))
                print('*** TEST FAILED ***')
                return False
            # Any or all of the following could fail.
            isok = True
            if md5 or md5match or opts.checksum:
                # All of these need the checksum computed
                val = self.canonical_checksum()
                if opts.checksum:
                    print('--- checksum:', val)
                if md5match:
                    prevval = md5map.get(md5match)
                    if prevval is None:
                        md5map[md5match] = val
                    else:
                        if val != prevval:
                            note_error(self, 'Game files mismatch [%s]: %s is not %s' % (md5match, val, prevval,))
                            print('*** TEST FAILED ***')
                            isok = False
                if md5 and val != md5:
                    note_error(self, 'Game file mismatch: %s is not %s' % (val, md5,))
                    print('*** TEST FAILED ***')
                    isok = False
            if abbreviations is not None:
                s1 = set(abbreviations)
                s2 = set(self.abbreviations)
                if s1 != s2:
                    note_error(self, 'Abbreviations list mismatch: missing %s, extra %s' % (list(s1-s2), list(s2-s1),))
                    print('*** TEST FAILED ***')
                    isok = False
            if warnings is not None:
                if self.warnings != warnings:
                    note_error(self, 'Warnings mismatch: expected %s but got %s' % (warnings, self.warnings,))
                    print('*** TEST FAILED ***')
                    isok = False
            if opts.runreg and reg is not None:
                if type(reg) is str:
                    regls = [ reg ]
                else:
                    regls = reg
                for reg in regls:
                    if not self.run_regtest(reg):
                        isok = False
            if debugfile is not None:
                val = self.canonical_debugfile_checksum('build/gameinfo.dbg')
                if val != debugfile:
                    note_error(self, 'gameinfo.dbg mismatch: %s is not %s' % (val, debugfile,))
                    print('*** TEST FAILED ***')
                    isok = False
            return isok
        note_error(self, 'Should be ok, but was: %s' % (self,))
        print('*** TEST FAILED ***')
        return False

    def is_memsetting(self, val):
        """ Assert that the compile threw a recognized error.
        This checks the *first* error recognized; see above.
        (This also checks the fatal "increase $SETTING" errors that
        Inform used to throw.)
        """
        if (self.status == Result.ERROR and self.memsetting == val):
            return True
        note_error(self, 'Should be error (%s), but was: %s' % (val, self,))
        print('*** TEST FAILED ***')
        return False

    def is_error(self, warnings=None, errors=None):
        """ Assert that the compile failed, but *not* with an
        "increase $SETTING" error.
        """
        if (self.status == Result.ERROR and not self.memsetting):
            if errors is not None:
                if self.errors != errors:
                    note_error(self, 'Errors mismatch: expected %s but got %s' % (errors, self.errors,))
                    print('*** TEST FAILED ***')
                    return False
            if warnings is not None:
                if self.warnings != warnings:
                    note_error(self, 'Warnings mismatch: expected %s but got %s' % (warnings, self.warnings,))
                    print('*** TEST FAILED ***')
                    return False
            return True
        note_error(self, 'Should be error, but was: %s' % (self,))
        print('*** TEST FAILED ***')
        return False

    def run_regtest(self, reg):
        regfile = os.path.join('reg', reg)
        if not os.path.exists(regfile):
            note_error(self, 'Regression test file does not exist: %s' % (regfile,))
            return False
        # Oughta add options for the remterp selection...
        if self.glulx:
            rterp = 'glulxer --rngseed 1'
            userem = True
        else:
            rterp = 'bocfelr -z 1'
            userem = True
        argls = [ opts.regtest, '--interpreter', rterp, '--game', self.filename, regfile ]
        if userem:
            argls.insert(1, '--rem')
        if opts.stdout:
            argls.append('--verbose')
        printargls = [ "'"+val+"'" if ' ' in val else val for val in argls ]
        print('...then:', ' '.join(printargls))
        try:
            subprocess.run(argls, check=True, capture_output=True, encoding='utf8')
        except subprocess.CalledProcessError as ex:
            errtext = '...'+ex.stdout.replace('\n', '\n...')
            note_error(self, 'Regression test failed: %s\n%s' % (regfile, errtext))
            return False
        return True

def set_testname(val):
    """Set the current test name. (Used for error output.)
    """
    global testname
    testname = val
    print()
    print('* Test:', testname)
    print()
    
def note_error(res, msg):
    """Note an error in the global error list.
    """
    label = '-'
    if res:
        label = res.srcfile
        if res.args:
            label += ' ' + ' '.join(res.args)
    errorlist.append( (testname, label, msg) )
    if opts.vital:
        raise Exception('aborting after one error')

class TestGroup:
    """TestGroup: Base class for a group of tests.

    A test group will be represented as a class. We don't instantiate the
    class; it's just a grouping mechanism really. This base class has
    machinery to gather up all Test instances defined in its scope and
    stuff them into a list in the class object. The class object, in turn,
    is stuffed into the TestGroup.groups[] list.

    (Don't make that face. I could have used decorators. Or metaclasses.)
    """
    accumtests = []
    groups = []
    
    def __init_subclass__(cla, key, **kwargs):
        super().__init_subclass__(**kwargs)
        cla.key = key
        cla.tests = TestGroup.accumtests
        TestGroup.accumtests = []
        for test in cla.tests:
            test.group = key
        TestGroup.groups.append(cla)

    @classmethod
    def runtests(cla, filters=[]):
        if not filters:
            ls = cla.tests
        else:
            ls = []
            for test in cla.tests:
                if any([ test.match(filter) for filter in filters ]):
                    ls.append(test)
        if not ls:
            return
        set_testname(cla.key)
        for test in ls:
            testlist.append(test)
            test.run()

class Test:
    """One test. This contains the information needed to run the test --
    that is, to call compile() and then call is_ok() (or etc) on the Result
    that returns.

    (If this tool were better organized, compile() would be a method of this
    class. But it's evolved in stages.)

    Tests should only be instantiated in the body of a TestGroup class.
    """
    def __init__(self, filename, **kwargs):
        self.filename = filename
        if 'res' not in kwargs:
            raise Exception('Test has no res=')
        self.res = kwargs.pop('res')
        self.args = kwargs
        self.group = None
        
        TestGroup.accumtests.append(self)

    def __repr__(self):
        return '<Test %s: "%s">' % (self.group, self.filename,)

    def match(self, filter):
        if self.filename == filter:
            return True
        if fnmatch.fnmatch(self.filename, filter):
            return True
        return False

    def run(self):
        res = compile(self.filename, **self.args)
        wanted, args = self.res
        if wanted == 'OK':
            res.is_ok(**args)
        elif wanted == 'ERROR':
            res.is_error(**args)
        elif wanted == 'MEMSETTING':
            res.is_memsetting(args)
        else:
            raise Exception('test had no outcome: %s' % (self,))

def _ok(**kwargs):
    return ('OK', kwargs)
    
def _error(**kwargs):
    return ('ERROR', kwargs)
    
def _memsetting(name):
    return ('MEMSETTING', name)
    
# And now, the tests themselves.

class Run_Checksum(TestGroup, key='CHECKSUM'):
    Test('minimal_test.inf',
         res=_ok(md5='90866a483312a4359bc00db776e6eed4', md5match='minimal_test:z', warnings=0))

    Test('minimal_test.inf', zversion=3,
         res=_ok(md5='6143c98e20a44d843c1a6fbe2c19ecae'))

    Test('minimal_test.inf', zversion=4,
         res=_ok(md5='f82709a196ebbefe109525084220c35a'))

    Test('minimal_test.inf', zversion=5,
         res=_ok(md5='90866a483312a4359bc00db776e6eed4', md5match='minimal_test:z'))

    Test('minimal_test.inf', zversion=6,
         res=_ok(md5='08b59209daa947437a5119b8060522ef'))

    Test('minimal_test.inf', zversion=6, bigmem=True,
         res=_ok(md5='e273d746baf6dac4324c95e45982bec0'))

    Test('minimal_test.inf', zversion=7,
         res=_ok(md5='26bd70faebf8c61638a736a72f57c7ad'))

    Test('minimal_test.inf', zversion=7, bigmem=True,
         res=_ok(md5='814c9ac5777674f1cc98f9a0cd22d6da'))

    Test('minimal_test.inf', zversion=8,
         res=_ok(md5='fa7fc9bbe032d27355b0fcf4fb4f2c53'))

    Test('minimal_test.inf', glulx=True,
         res=_ok(md5='6e647107c3b3c46fc9556da0330db3a6', md5match='minimal_test:g', warnings=0))
    
    Test('glulxercise.inf', glulx=True,
         res=_ok(md5='edcb2b211fe5ab2afba62d50b66dad95', warnings=0))
    
    Test('i7-min-6G60.inf',
         res=_ok(md5='37401d71331bcec07cf44c73f5474b44', md5match='i7-min-6G60:z', reg='i7-min-6G60.reg'))

    Test('i7-min-6G60.inf', zversion=8,
         res=_ok(md5='14d9fabfc427dae8087ada57a51c72e1', reg='i7-min-6G60.reg'))

    Test('i7-min-6G60.inf', glulx=True,
         res=_ok(md5='f5811c171bd7f5bf843dfe813ef96e2f', md5match='i7-min-6G60:g', reg='i7-min-6G60.reg'))

    Test('i7-min-6M62-z.inf', zversion=8,
         res=_ok(md5='40f3782f9a3f0dd0ef973608d0bf4a92', reg='i7-min-6M62.reg'))

    Test('i7-min-6M62-g.inf', glulx=True,
         res=_ok(md5='00ef3d5fb6c9ac7c72dfab453c649843', reg='i7-min-6M62.reg'))

    Test('i7-min-10-1-2.inf', glulx=True,
         res=_ok(md5='1bcf7b52363ef91fe17398bd70787740', reg='i7-min-10.reg'))

    Test('Advent.inf', includedir='i6lib-611',
         res=_ok(md5='4b60c92f0e1d0b7735a6b237b1b99733', md5match='Advent:z', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8,
         res=_ok(md5='2ed4f9a623ad7e3c5407c7f8fca5d59a', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='6ba4eeca5bf7834488216bcc1f62586c', md5match='Advent:g', warnings=0, reg='Advent-g.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8, strict=False,
         res=_ok(md5='93d3e6578bbcf61e7043dd8ba8cb2bb9', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True, strict=False,
         res=_ok(md5='c3bc7b1edf47b4e6afa352d074645b45', warnings=0, reg='Advent-g.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8, debug=True,
         res=_ok(md5='5945168721934c5a503f7093412b60e2', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True, debug=True,
         res=_ok(md5='bb0d1f33ade0d7053ad5475b2414e311', warnings=0, reg='Advent-g.reg'))

    Test('Advent.inf', includedir='i6lib-611', infix=True,
         res=_ok(md5='e99660354a805f0fb81e83f51c7adc87', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-6.12.6',
         res=_ok(md5='96112c01dad9566b093af9ac7f20100c', warnings=0))

    Test('Advent.inf', includedir='i6lib-6.12.6', glulx=True,
         res=_ok(md5='cc4cf1f29c0a069fec6fba2803585f78', warnings=1))

    Test('box_quote_test.inf', includedir='i6lib-611',
         res=_ok(md5='30b3cf9158ad2090a4c1ffd007082203', warnings=0))

    Test('cloak-metro84-v3test.inf', zversion=3, economy=False,
         res=_ok(md5='5dbb60d4443147e514ea455a4be3699d', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=4, economy=False,
         res=_ok(md5='fe96744c98127a3c9a3039c893123825', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=5, economy=False,
         res=_ok(md5='d3ff2494e6db20aac3b91c57ed080a9e', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=3, economy=True,
         res=_ok(md5='3a40b16e55a52f32491de0993e336281', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=4, economy=True,
         res=_ok(md5='db22d3ec53d9198928642b293e6502f5', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=5, economy=True,
         res=_ok(md5='cdaec89d23a7c9f715f34c4ae8b9cbe3', warnings=2, reg='cloak-metro84.reg'))

    Test('library_of_horror-16.inf', includedir='punylib-16', zversion=3,
         res=_ok(md5='e25ff15276ad392a17fbb7b5a65e4d4b'))

    Test('library_of_horror-16.inf', includedir='punylib-16', zversion=3, memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='ea95187ecd621d0735388f4ec88e2cde'))

    # OMIT_UNUSED_ROUTINES is set in the source
    Test('library_of_horror-36.inf', includedir='punylib-36', zversion=3,
         res=_ok(md5='96d3cd8e86b5f663f010cfb2355eb031', reg='library_of_horror.reg'))

    # OMIT_UNUSED_ROUTINES is set in the source; GV3 is set in the library.
    Test('library_of_horror-60.inf', includedir='punylib-60', zversion=3,
         res=_ok(md5='5b4eccb1d11ddec766ffed58e9564110', reg='library_of_horror.reg'))
    
    Test('library_of_horror-60.inf', includedir='punylib-60', zversion=3, memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='4b1d55b7da337329f6cd34852efa0b6a', md5match='library_of_horror-60:meta=1', reg='library_of_horror.reg'))


class Run_Dict(TestGroup, key='DICT'):
    Test('dict-size-v3test.inf', zversion=3,
         res=_ok(md5='68b57b14d5ca770be53134d8f4739727', reg='allpass.reg'))

    Test('dict-size-v3test.inf', zversion=5,
         res=_ok(md5='18bfce12d6b8bb36b5d4b05286710568', reg='allpass.reg'))

    Test('dict-cutoff-v3test.inf', strict=False, zversion=3,
         res=_ok(md5='20b161aaaebf35702861f482dcd41e41', reg='allpass.reg'))

    Test('dict-cutoff-v3test.inf', strict=False, zversion=4,
         res=_ok(md5='d928d1c782fdfec1c0be8770b3dcdac9', reg='allpass.reg'))

    Test('dict-cutoff-v3test.inf', strict=False, zversion=5,
         res=_ok(md5='764627f02bd22d68936fa4ade2fc41bf', reg='allpass.reg'))

    # This messes with the alphabet, which changes the output.
    Test('dict-cutoff-alttest.inf', strict=False, zversion=4,
         res=_ok(md5='ec891cebd947ebb39400580e26bf2365', reg='dict-cutoff-alttest-v4.reg'))

    Test('dict-cutoff-alttest.inf', strict=False, zversion=5,
         res=_ok(md5='242b4bb8b2bfbbf6d71b63091458ac9d', reg='allpass.reg'))

    Test('dict-cutoff-alttest.inf', strict=False, zversion=8,
         res=_ok(md5='3a7138549bfc228342d8ef944a77ff86', reg='allpass.reg'))

    Test('max_dict_entries.inf',
         res=_ok())

    Test('max_dict_entries.inf', glulx=True,
         res=_ok())

    Test('dict-entry-size-test.inf', zversion=3, strict=False,
         res=_ok(md5='015b14adf6ed2653cc61f1c57eadbcbc'))

    # The checksum here is different because the "Version 3" directive doesn't work perfectly
    Test('dict-entry-size-test.inf', zversion=3, strict=False, define={'EARLYDEF':None}, versiondirective=True,
         res=_ok(md5='5df7a75b03a530d06397fbc51a58133c'))

    # Cannot put Version directive at the end
    Test('dict-entry-size-test.inf', zversion=3, strict=False, define={'LATEDEF':None}, versiondirective=True,
         res=_error())

    # Warning about "Dictionary 'w' x y" directive
    Test('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1}, define={'TRYDICT3':None},
         res=_ok(warnings=1))

    Test('dict-entry-size-test.inf', zversion=3, strict=False, define={'TRYVERB':None},
         res=_ok())

    # Cannot use GV1 with ZCODE_LESS_DICT_DATA
    Test('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1}, define={'TRYVERB':None},
         res=_error())

    Test('dict-entry-size-test.inf', zversion=3, strict=False, define={'TRYPAR3':None},
         res=_ok())

    # Cannot use #dict_par3 with ZCODE_LESS_DICT_DATA
    Test('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1}, define={'TRYPAR3':None},
         res=_error())

    Test('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1},
         res=_ok(md5='ff7005f93c1ff23adb38eb83e47df385'))

    Test('dict-entry-size-test.inf', zversion=5,
         res=_ok(md5='51df8efdda4d3054c4ae85832c5feff4'))

    Test('dict-entry-size-test.inf', zversion=5, memsettings={'ZCODE_LESS_DICT_DATA':1},
         res=_ok(md5='add36cb334e2adfad71e5c3d07907876'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_LESS_DICT_DATA':1},
         res=_ok(md5='fb019908da1001bd02aa2564997ff87f', warnings=0, reg='Advent-z.reg'))

    Test('dict-sysconst-test.inf',
         res=_ok(md5='cd5237d6645df57e78e214e5ed70828c', reg='allpass.reg'))

    Test('dictlongflagtest.inf',
         res=_ok(md5='0d78b9f9117afe5be3047a911b0a0952'))

    Test('dictlongflagtest.inf', zversion=3,
         res=_ok(md5='22c158dc4fb8feb61f4cd6fc5983041c'))

    Test('dictlongflagtest.inf', glulx=True,
         res=_ok(md5='cc6c969d085fae001fde77c335973e28'))

    Test('dictlongflagtest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':10},
         res=_ok(md5='fd13c0fbcf994af91342ea3d6d65a0ff'))

    Test('dictlongflagtest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':11},
         res=_ok(md5='a55c2608cfbd93eedbeaec99c24d85bd'))

    Test('dictlongflagtest.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='eec2db33148b1f95660823a5b9e97482'))

    Test('dictlongflagtest.inf', define={'BADFLAG':None},
         res=_ok(md5='ca030580d46f2caf4f572c059540aab8'))
    
    Test('dictlongflagtest.inf', glulx=True, define={'BADFLAG':None},
         res=_ok(md5='3b79154a39bb1e11e6d21b40b158110b'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0},
         res=_ok(md5='7c7ef0506b467dd94b6615c6da88fcff'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, zversion=3,
         res=_ok(md5='1bfad5368945e03d4c71d2a34eea9912'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True,
         res=_ok(md5='d38418d3900bd545dfb5bab3eebd222e'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_WORD_SIZE':10}, glulx=True,
         res=_ok(md5='794b616e86813b0d396b4e8e845b120f'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_WORD_SIZE':11}, glulx=True,
         res=_ok(md5='70ddb5e68b3a28aaf9b68a424b891a98'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_CHAR_SIZE':4}, glulx=True,
         res=_ok(md5='c0e051373b7affadd68e50001faabc8c'))

    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, define={'BADFLAG':None},
         res=_error())
    
    Test('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True, define={'BADFLAG':None},
         res=_error())

    Test('i7-min-6M62-z.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, zversion=8,
         res=_ok(md5='942c4f87b212f13d219c53aaf54b6008', reg='i7-min-6M62.reg'))

    Test('i7-min-6M62-g.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True,
         res=_ok(md5='132880fc7f9ce5ae3deb1c72784a208b', reg='i7-min-6M62.reg'))

    Test('dictnewflagtest.inf',
         res=_ok(md5='6a46be13dad0cb7ea0bb3b055427615a'))
    
    Test('dictnewflagtest.inf', glulx=True,
         res=_ok(md5='097c61acb854a80cfb2fd5cae9e72d48'))
    
    Test('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0},
         res=_ok(md5='79b88af5e431f59ddea6bbb28d47ffd8'))
    
    Test('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True,
         res=_ok(md5='b8b2c4ca7553a85b69ca5435a6a5cee7'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_IMPLICIT_SINGULAR':1},
         res=_ok(md5='8ce940f818408b04c8cd3e6c05119b1f'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_IMPLICIT_SINGULAR':1}, glulx=True,
         res=_ok(md5='ee0a007647fa8f58f2358665fe93e744'))
    
    Test('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_IMPLICIT_SINGULAR':1},
         res=_ok(md5='537f36822afb31ab7cfa8c503ea965a5'))
    
    Test('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_IMPLICIT_SINGULAR':1}, glulx=True,
         res=_ok(md5='2acd0a25997ca335b5ae07a9bd4e4561'))
    
    Test('dictnewflagtest.inf', define={'BADFLAG1':None},
         res=_error())
    
    Test('dictnewflagtest.inf', define={'BADFLAG2':None},
         res=_error())
    
    Test('dictnewflagtest.inf', glulx=True, define={'BADFLAG1':None},
         res=_error())
    
    Test('dictnewflagtest.inf', glulx=True, define={'BADFLAG2':None},
         res=_error())
    
    Test('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1},
         res=_ok(md5='05ca1b8acf37340582c8fb075eb3f14a'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1}, glulx=True,
         res=_ok(md5='6d2fae4684f6f17b93341588fd407e7d'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'LONG_DICT_FLAG_BUG':0},
         res=_ok(md5='41c779bc75fad0e85703fd2b9bc14912'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'LONG_DICT_FLAG_BUG':0}, glulx=True,
         res=_ok(md5='a5d8c864a7400e349f32e8261deba92d'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'DICT_IMPLICIT_SINGULAR':1, 'LONG_DICT_FLAG_BUG':1, 'DICT_WORD_SIZE':10}, glulx=True,
         res=_ok(md5='d3def326e708a7848c7257696e74f518'))
    
    Test('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'DICT_IMPLICIT_SINGULAR':1, 'LONG_DICT_FLAG_BUG':0, 'DICT_WORD_SIZE':10}, glulx=True,
         res=_ok(md5='d3def326e708a7848c7257696e74f518'))
    
    Test('Advent.inf', includedir='i6lib-611w,i6lib-611',
         res=_ok(md5='11d7b1c894a7efe08a66ee43ac9f5d6e', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611w,i6lib-611', glulx=True,
         res=_ok(md5='dac7d96a50a17472941feaa8bdd87ef0', warnings=0, reg='Advent-g.reg'))

    Test('dictlargeentrytest.inf', glulx=True,
         res=_ok(md5='aa96bddd17fc8fbe78871d9f4088df1a', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='70c228f06ee6b3c5af55851480141437', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':30},
         res=_ok(md5='e690c593b10fde1dd87a3498007452be', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':30, 'DICT_CHAR_SIZE':4},
         res=_ok(md5='457a3de16ef58dc96056e090c97fcabc', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':35},
         res=_ok(md5='cf5c66f2e71b1660a5a78b8ad6968d5d', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':35, 'DICT_CHAR_SIZE':4},
         res=_ok(md5='19116031757220e8fa01b1d88aadd664', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':144},
         res=_ok(md5='b19c63f5ed6e8738b84aa6889daf5d85', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':144, 'DICT_CHAR_SIZE':4},
         res=_ok(md5='d42460263e3fe758098c7b975f994239', reg='allpass.reg'))
    

class Run_Grammar(TestGroup, key='GRAMMAR'):
    # File compiles the same whether the grammar version is set by Constant or compiler option
    
    Test('grammar-version-test.inf',
         res=_ok(md5='d9dfd1f956beeeff947a30c4617dab48', md5match='grammar-version-test:gv=1'))

    Test('grammar-version-test.inf', define={'SET_GV_1':None},
         res=_ok(md5='d9dfd1f956beeeff947a30c4617dab48', md5match='grammar-version-test:gv=1'))

    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':1},
         res=_ok(md5='d9dfd1f956beeeff947a30c4617dab48', md5match='grammar-version-test:gv=1'))

    Test('grammar-version-test.inf', define={'SET_GV_2':None},
         res=_ok(md5='d0c7c637051334c0886d4ea1500837f2', md5match='grammar-version-test:z:gv=2'))

    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':2},
         res=_ok(md5='d0c7c637051334c0886d4ea1500837f2', md5match='grammar-version-test:z:gv=2'))

    Test('grammar-version-test.inf', glulx=True,
         res=_ok(md5='d47bae32d9bd18f7f2dbd80577795398', md5match='grammar-version-test:g:gv=2'))

    Test('grammar-version-test.inf', glulx=True, define={'SET_GV_2':None},
         res=_ok(md5='d47bae32d9bd18f7f2dbd80577795398', md5match='grammar-version-test:g:gv=2'))

    Test('grammar-version-test.inf', glulx=True, memsettings={'GRAMMAR_VERSION':2},
         res=_ok(md5='d47bae32d9bd18f7f2dbd80577795398', md5match='grammar-version-test:g:gv=2'))

    Test('grammar-version-test.inf', define={'SET_GV_3':None},
         res=_ok(md5='4516571efb9e088b090f6e7536a7031a', md5match='grammar-version-test:gv=3'))

    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':3},
         res=_ok(md5='4516571efb9e088b090f6e7536a7031a', md5match='grammar-version-test:gv=3'))

    # two constants decls, the later one wins
    Test('grammar-version-test.inf', define={'SET_GV_2':None, 'SET_GV_3':None},
         res=_ok(md5='4516571efb9e088b090f6e7536a7031a', md5match='grammar-version-test:gv=3'))
    
    # command-line setting overrides constant decl
    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':3}, define={'SET_GV_2':None},
         res=_ok(md5='4516571efb9e088b090f6e7536a7031a', md5match='grammar-version-test:gv=3'))

    # command-line setting overrides constant decl
    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':2}, define={'SET_GV_3':None},
         res=_ok(md5='d0c7c637051334c0886d4ea1500837f2', md5match='grammar-version-test:z:gv=2'))

    # command-line setting overrides constant decl
    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':2}, define={'SET_GV_4':None},
         res=_ok(md5='d0c7c637051334c0886d4ea1500837f2', md5match='grammar-version-test:z:gv=2'))

    # header comment overrides constant decl
    Test('grammar-headversion-test.inf', define={'SET_GV_2':None},
         res=_ok(md5='4516571efb9e088b090f6e7536a7031a', md5match='grammar-version-test:gv=3'))

    # command-line setting overrides both
    Test('grammar-headversion-test.inf', memsettings={'GRAMMAR_VERSION':1}, define={'SET_GV_2':None},
         res=_ok(md5='d9dfd1f956beeeff947a30c4617dab48', md5match='grammar-version-test:gv=1'))

    Test('grammar-version-test.inf', glulx=True, define={'SET_GV_3':None},
         res=_error())

    Test('grammar-version-test.inf', glulx=True, memsettings={'GRAMMAR_VERSION':3},
         res=_error())

    Test('grammar-version-test.inf', define={'SET_GV_4':None},
         res=_error())

    Test('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':4},
         res=_error())

    Test('grammar-version-test.inf', glulx=True, define={'SET_GV_4':None},
         res=_error())

    Test('grammar-version-test.inf', glulx=True, memsettings={'GRAMMAR_VERSION':4},
         res=_error())

    # Fake_Action before Grammar__Version 2
    Test('grammar-version-test.inf', define={'EARLY_FAKE_ACTION':None, 'SET_GV_2':None},
         res=_error())

    # Real action before Grammar__Version 2
    Test('grammar-version-test.inf', define={'EARLY_ACTION_VERB':None, 'SET_GV_2':None},
         res=_error())

    # ##Action before Grammar__Version 2
    Test('grammar-version-test.inf', define={'EARLY_ACTION_CONST':None, 'SET_GV_2':None},
         res=_ok())

    # action-case before Grammar__Version 2
    Test('grammar-version-test.inf', define={'EARLY_ACTION_CASE':None, 'SET_GV_2':None},
         res=_ok())

    # non-constant Grammar__Version
    Test('grammar-version-test.inf', define={'SET_GV_NONCONST':None},
         res=_error())

    # Same as i7-min-6G60.inf, except we set the grammar by option
    Test('i7-min-6G60-gvopt.inf',
         res=_ok(md5='37401d71331bcec07cf44c73f5474b44', md5match='i7-min-6G60:z', reg='i7-min-6G60.reg'))

    # Advent with GRAMMAR_META_FLAG should run correctly
    Test('Advent.inf', includedir='i6lib-611', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='f9c856a53a5f0a825c8baa182a4035d1', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True, memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='80c3887b4c8c98c861c5c24a6a40c62c', warnings=0, reg='Advent-g.reg'))

    # Requires GRAMMAR_META_FLAG
    Test('grammar-metaflag-test.inf',
         res=_error())

    Test('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='842c386354b653e09f318a5ea4ab9a3b', reg='allpass.reg'))

    Test('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1, 'GRAMMAR_VERSION':2},
         res=_ok(md5='9e79016c78590c011496806a7fa4acce', reg='allpass.reg'))

    Test('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, glulx=True,
         res=_ok(md5='b00bcb640c314ca7e28571deadfc6612', reg='allpass.reg'))


    Test('grammar-metaconst-test.inf',
         res=_ok(md5='0731d623fc67675539aeb8f4ccddbb76', md5match='grammar-metaconst-test:meta=0'))

    Test('grammar-metaconst-test.inf', memsettings={'GRAMMAR_META_FLAG':0},
         res=_ok(md5='0731d623fc67675539aeb8f4ccddbb76', md5match='grammar-metaconst-test:meta=0'))

    Test('grammar-metaconst-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='1a67edeeaa3af94ca857ca41f6b97542', md5match='grammar-metaconst-test:meta=1'))

    Test('grammar-metaconst-test.inf', define={'SET_META_0':None},
         res=_ok(md5='0731d623fc67675539aeb8f4ccddbb76', md5match='grammar-metaconst-test:meta=0'))

    Test('grammar-metaconst-test.inf', define={'SET_META_1':None},
         res=_ok(md5='1a67edeeaa3af94ca857ca41f6b97542', md5match='grammar-metaconst-test:meta=1'))

    Test('grammar-metaconst-test.inf', define={'SET_META_2':None},
         res=_error())

    Test('grammar-metaconst-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, define={'SET_META_0':None},
         res=_ok(md5='1a67edeeaa3af94ca857ca41f6b97542', md5match='grammar-metaconst-test:meta=1'))

    Test('grammar-metaconst-test.inf', memsettings={'GRAMMAR_META_FLAG':0}, define={'SET_META_1':None},
         res=_ok(md5='0731d623fc67675539aeb8f4ccddbb76', md5match='grammar-metaconst-test:meta=0'))

    Test('grammar-metaconst-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, define={'SET_META_2':None},
         res=_ok(md5='1a67edeeaa3af94ca857ca41f6b97542', md5match='grammar-metaconst-test:meta=1'))

    # Fake_Action before Grammar_Meta__Value 1
    Test('grammar-metaconst-test.inf', define={'EARLY_FAKE_ACTION':None, 'SET_META_1':None},
         res=_error())

    # Real action before Grammar_Meta__Value 1
    Test('grammar-metaconst-test.inf', define={'EARLY_ACTION_VERB':None, 'SET_META_1':None},
         res=_error())

    # ##Action before Grammar_Meta__Value 1
    Test('grammar-metaconst-test.inf', define={'EARLY_ACTION_CONST':None, 'SET_META_1':None},
         res=_error())

    # action-case before Grammar_Meta__Value 1
    Test('grammar-metaconst-test.inf', define={'EARLY_ACTION_CASE':None, 'SET_META_1':None},
         res=_error())

    # non-constant Grammar_Meta__Value
    Test('grammar-metaconst-test.inf', define={'SET_META_NONCONST':None},
         res=_error())

    

    Test('action-compare-test.inf',
         res=_ok(md5='67f8fe8fa78eb656aaa13b027e5d38fb', reg='allpass.reg'))

    Test('action-compare-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='a96187c6d5bf147be5f57fb52e7f6e38', reg='allpass.reg'))

    Test('action-compare-test.inf', glulx=True,
         res=_ok(md5='08e17d252a3c99e498f13bb421391436', reg='allpass.reg'))

    Test('action-compare-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, glulx=True,
         res=_ok(md5='62701429bcb915e44fd5e65807a72448', reg='allpass.reg'))

    
    Test('grammar-dump-test.inf',
         res=_ok(md5='877fea7aa94bb6682825a086640673c9', reg='grammardump-gv1.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2},
         res=_ok(md5='63c730fa3e796cfb5616764c382b53a8', reg='grammardump-gv2.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':3},
         res=_ok(md5='dbaf2cea0a48221e07ca071ac0be31e6', reg='grammardump-gv3.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2}, glulx=True,
         res=_ok(md5='a026e3913f038ca15ddcf27fd240fc92', reg='grammardump-gv2.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='a51e3cd1a30c21b3918e7334a7b60857', reg='grammardump-gv1-meta.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2, 'GRAMMAR_META_FLAG':1},
         res=_ok(md5='6e3cfb41dbd3c596852cb5fa8f965f46', reg='grammardump-gv2-meta.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':3, 'GRAMMAR_META_FLAG':1},
         res=_ok(md5='457a0d28ed78b9d0d21c44d1c4eebb34', reg='grammardump-gv3-meta.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2, 'GRAMMAR_META_FLAG':1}, glulx=True,
         res=_ok(md5='646f05fd1f31d52d270c6be0d7482149', reg='grammardump-gv2-meta.reg'))
    
    
    # Compile with the GV3 parser.
    Test('Advent.inf', includedir='i6lib-611gv3,i6lib-611',
         res=_ok(md5='aa60a6556911766ed2e81528cd460fab', warnings=0, reg='Advent-z.reg'))

    # Compile with GRAMMAR_META_FLAG
    Test('library_of_horror-60.inf', includedir='punylib-60meta,punylib-60', zversion=3,
         res=_ok(md5='4b1d55b7da337329f6cd34852efa0b6a', md5match='library_of_horror-60:meta=1'))

    # Compile with the modified parser; meta verbs should be meta.
    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', memsettings={'GRAMMAR_META_FLAG':1}, debug=True,
         res=_ok(md5='d4cee3d70101961d07866fbb706f524d', md5match='withdaemon:z:meta=1', warnings=0))
    
    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', debug=True, define={'SET_META_CONST':None},
         res=_ok(md5='d4cee3d70101961d07866fbb706f524d', md5match='withdaemon:z:meta=1', warnings=0))
    
    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', memsettings={'GRAMMAR_META_FLAG':1}, debug=True, glulx=True,
         res=_ok(md5='6d07796bd4bc8b9dd5b3f233eadba309', md5match='withdaemon:g:meta=1', warnings=0))

    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', define={'SET_META_CONST':None}, debug=True, glulx=True,
         res=_ok(md5='6d07796bd4bc8b9dd5b3f233eadba309', md5match='withdaemon:g:meta=1', warnings=0))

    
    # All of the following should compile the same.
    Test('verbclash.inf', includedir='i6lib-611', define={'EXTENDLAST':None},
         res=_ok(md5='ca9573896d5a8492244f3dc4b28d0a8e', md5match='verbclash', warnings=0))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'EXACTSAME':None},
         res=_ok(md5='ca9573896d5a8492244f3dc4b28d0a8e', md5match='verbclash', warnings=1))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'CASESAME':None},
         res=_ok(md5='ca9573896d5a8492244f3dc4b28d0a8e', md5match='verbclash', warnings=1))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'TRUNCSAME':None},
         res=_ok(md5='ca9573896d5a8492244f3dc4b28d0a8e', md5match='verbclash', warnings=1))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'DIFFERENTVERBS1':None},
         res=_error())
    
    Test('verbclash.inf', includedir='i6lib-611', define={'DIFFERENTVERBS2':None},
         res=_error())
    
    Test('verbclash.inf', includedir='i6lib-611', define={'DIFFERENTVERBS3':None},
         res=_error())
    
    Test('verbclash.inf', includedir='i6lib-611', define={'NOVERBS':None},
         res=_error())
    
    Test('verbclash.inf', includedir='i6lib-611', define={'NOTAVERB':None},
         res=_error())
    
    Test('verbclash.inf', includedir='i6lib-611', define={'BADEQUALS':None},
         res=_error())
    
    Test('verbclash.inf', includedir='i6lib-611', define={'BADEQUALS2':None},
         res=_error())
    
    
class Run_Encoding(TestGroup, key='ENCODING'):
    Test('unisourcetest.inf', glulx=True,
         res=_ok(md5='e8d37802d6ca98f4f8c31ac5068b0dbc', reg='unisourcetest.reg'))
    
    Test('source-encoding-1.inf',
         res=_ok(md5='f303584ce078db2277577e34e82f88d6', reg='source-encoding-1.reg'))

    # No output check because the file has no Glk setup
    Test('source-encoding-1.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='946b2540327fdff54b0ffd93922317f2'))
    
    Test('source-encoding-7.inf',
         res=_ok(md5='4080e4a3d95c01afacf6904010492df5', reg='source-encoding-7.reg'))

    # No output check because the file has no Glk setup
    Test('source-encoding-7.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='175f2b60c6347197eec2225e85702e75'))
    
    Test('source-encoding-u.inf',
         res=_ok(md5='0a3b48f42fb285dda46b2fda4b13cee3', reg='source-encoding-u.reg'))

    # No output check because the file has no Glk setup
    Test('source-encoding-u.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='6211a900cfa1ca2d84ae2eb065efeb47'))

    Test('zalphabet-direct.inf',
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))
    
    Test('zalphabet-header.inf',
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-header-esc.inf',
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-:()'},
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789@{2E},!?_@{00023}\'/\\-:()'},
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    # One char short
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 123456789.,!?_#\'/\\-:()'},
         res=_error())

    # One char long
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-:()$'},
         res=_error())

    # Non-ASCII
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-\xE4()'},
         res=_error())

    # Empty braces
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-@{}()'},
         res=_error())

    # Non-hex character in braces
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-@{123x}()'},
         res=_error())

    # Unterminated braces
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-()@{123'},
         res=_error())

    
class Run_Lexer(TestGroup, key='LEXER'):
    Test('long_identifier_test.inf',
         res=_ok())

    Test('long_identifiers_2.inf',
         res=_ok())

    Test('long_identifiers_2.inf', glulx=True,
         res=_ok())

    # Object short names are over 765 Z-chars
    Test('long_identifiers_3.inf',
         res=_memsetting('MAX_SHORT_NAME_LENGTH'))

    Test('long_identifiers_3.inf', glulx=True,
         res=_ok())

    Test('long_dictword_test.inf',
         res=_ok())

    Test('unclosed_double_quote.inf',
         res=_error())

    Test('unclosed_single_quote.inf',
         res=_error())

    Test('unclosed_double_quote.inf',
         res=_error())

    Test('empty_single_quotes.inf',
         res=_error())

    Test('one_quote_single_quotes.inf',
         res=_ok())

    Test('linebreak-unix.inf',
         res=_ok(md5='c6141b8c15f81e3d1db728e5aaf1303b', md5match='linebreak', warnings=1))

    Test('linebreak-oldmac.inf',
         res=_ok(md5='c6141b8c15f81e3d1db728e5aaf1303b', md5match='linebreak', warnings=1))

    Test('linebreak-dos.inf',
         res=_ok(md5='c6141b8c15f81e3d1db728e5aaf1303b', md5match='linebreak', warnings=1))

    Test('icl-linebreak-unix.inf', glulx=True,
         res=_ok(md5='3067f025bcc31115e5ec7397761e2f41', md5match='icl-linebreak'))

    Test('icl-linebreak-dos.inf', glulx=True,
         res=_ok(md5='3067f025bcc31115e5ec7397761e2f41', md5match='icl-linebreak'))

    Test('icl-linebreak-oldmac.inf', glulx=True,
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('icl-semicolon.inf', glulx=True,
         res=_ok(md5='3067f025bcc31115e5ec7397761e2f41', md5match='icl-linebreak'))

    Test('bad-global.inf',
         res=_error())

    # we don't have a way to test this, but the error should be on line 9
    Test('action-const-err.inf',
         res=_error())

    Test('action-const-err.inf', define={'WITHCONST':None},
         res=_ok(md5='6583888936f6747ef6e65d38559f0a17'))

    
class Run_Directives(TestGroup, key='DIRECTIVES'):
    # md5 checks for serial.inf are useless because the checksummer ignores the serial number. Run the compiled file to check it.
    
    Test('serial.inf', define={'SETFIXEDSERIAL':None, 'CHECKYEAR':12, 'CHECKMONTH':34, 'CHECKDAY':56},
         res=_ok(reg='serial-1.reg'))
    
    Test('serial.inf', define={'SETFIXEDSERIAL':None, 'CHECKYEAR':12, 'CHECKMONTH':34, 'CHECKDAY':56}, glulx=True,
         res=_ok(reg='serial-1.reg'))
    
    Test('serial.inf', memsettings={'SERIAL':234567}, define={'CHECKYEAR':23, 'CHECKMONTH':45, 'CHECKDAY':67},
         res=_ok(reg='serial-2.reg'))
    
    Test('serial.inf', memsettings={'SERIAL':234567}, define={'CHECKYEAR':23, 'CHECKMONTH':45, 'CHECKDAY':67}, glulx=True,
         res=_ok(reg='serial-2.reg'))
    
    Test('serial.inf', define={'SETBADSERIAL1':None},
         res=_error())
    
    Test('serial.inf', define={'SETBADSERIAL2':None},
         res=_error())
    
    Test('staticarraytest.inf',
         res=_ok(md5='8ce988079de92ca008b566864cfbddc7', reg='staticarraytest-z.reg'))

    Test('staticarraytest.inf', glulx=True,
         res=_ok(md5='29abadec278f29e1c0b5eea0fd9c3495', reg='staticarraytest-g.reg'))

    Test('undefdirectivetest.inf',
         res=_ok(md5='4f7ad0f17634dec6df2a494b13823600'))

    Test('undefdirectivetest.inf', glulx=True,
         res=_ok(md5='b981cf8a2508c9d56b7c4593ac336048'))

    Test('no-main.inf',
         res=_error())

    Test('no-main.inf', define={'WRONGMAIN':None},
         res=_error())
    
    Test('no-main.inf', define={'FORWARDMAIN':None},
         res=_error())
    
    Test('no-main.inf', glulx=True,
         res=_error())

    Test('no-main.inf', glulx=True, define={'WRONGMAIN':None},
         res=_error())

    Test('no-main.inf', glulx=True, define={'FORWARDMAIN':None},
         res=_error())

    Test('replacerenametest.inf', includedir='src',
         res=_ok(md5='1d242a742cab1f2284550689c5bf9451'))

    Test('replacerenametest.inf', includedir='src', glulx=True,
         res=_ok(md5='0a1fc0c94e71b42e406d8401517636d4'))

    Test('replacerecursetest.inf',
         res=_ok(md5='831ccfc92382e9c17e4cc70fce773d49'))

    Test('replacerecursetest.inf', glulx=True,
         res=_ok(md5='2382f2a66978bdd09e42825bdeb551aa'))

    Test('dictflagtest.inf',
         res=_ok(md5='888c6763233a619d8f72f9b8f88360b6'))

    Test('dictflagtest.inf', glulx=True,
         res=_ok(md5='05d9526ea9c2bc9bf5fdb41c9e3024e1'))

    Test('actionextension.inf',
         res=_ok(md5='778d0a2f631fa8447a70a6cf1a66e931'))

    Test('actionextension.inf', glulx=True,
         res=_ok(md5='7d4bc338e99a777534f03d1a80388e58'))

    Test('internaldirecttest.inf',
         res=_ok(md5='1415fae596b55550451173cd81f0324b', reg='internaldirecttest.reg'))

    Test('internaldirecttest.inf', glulx=True,
         res=_ok(md5='8f7bef97e18c912ec45760b57de6fa66', reg='internaldirecttest.reg'))

    Test('ifelsedirecttest.inf',
         res=_ok(md5='b3af5667703d37238f0c822889118a47'))

    Test('ifelsedirecttest.inf', glulx=True,
         res=_ok(md5='c0724fca3f6783e10f7188ca4dbb1d3d'))

    Test('ifdef_vn_test.inf',
         res=_ok(md5='921033aea6fe468b347e376b1a9fde56'))

    Test('ifdef_vn_test.inf', glulx=True,
         res=_ok(md5='5ad58c728862dce11b17d7a93adaaa51'))

    Test('classordertest.inf',
         res=_ok(md5='34ef0f9fc9da5cd4202e51d1fd84808b', reg='allpass.reg'))

    Test('classordertest.inf', glulx=True,
         res=_ok(md5='4025856ed2133af211feda4aa187d1fe', reg='allpass.reg'))

    Test('classcopytest.inf',
         res=_ok(md5='a89385fc300471a0d268404b7395d3c3', reg='allpass.reg'))

    Test('classcopytest.inf', glulx=True,
         res=_ok(md5='9f6c50b53599e2a3dec440715759877d', reg='allpass.reg'))

    Test('forwardproptest.inf',
         res=_ok(md5='2dce9b5dcd3c4cac350eea05c4645e67', reg='allpass.reg'))

    Test('forwardproptest.inf', strict=False,
         res=_ok(md5='c410fc0e2b21052136cc9547544f98a8', reg='allpass.reg'))

    Test('forwardproptest.inf', glulx=True,
         res=_ok(md5='95095b05c3e5d9765822da3b725a108d', reg='allpass.reg'))

    Test('forwardproptest.inf', glulx=True, strict=False,
         res=_ok(md5='82029b0f66f3536734d46ea80c1dab6c', reg='allpass.reg'))

    Test('indivproptest.inf',
         res=_ok(md5='029c53472d82b6a09c4c0ec427a73b37', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None},
         res=_ok(md5='029c53472d82b6a09c4c0ec427a73b37', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV2':None},
         res=_ok(md5='56f1923126bea5d3f1d5ec401983950e', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None,'DEF_INDIV2':None},
         res=_ok(md5='c84011a690f944920ab394eb3e7ac5f1', reg='allpass.reg'))

    Test('indivproptest.inf', glulx=True,
         res=_ok(md5='fe01898bcf2f6b7639be92c213706252', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None}, glulx=True,
         res=_ok(md5='fe01898bcf2f6b7639be92c213706252', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV2':None}, glulx=True,
         res=_ok(md5='3e61c800eaeebbe7fc668acda9bf1be9', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None,'DEF_INDIV2':None}, glulx=True,
         res=_ok(md5='bda9d7dcc34ea1d463b336852a6d515b', reg='allpass.reg'))

    Test('indivproptest_2.inf',
         res=_ok(md5='a364d8a262e8a12ddb7325b4f2555e2b', warnings=0, reg='allpass.reg'))

    Test('indivproptest_2.inf', define={'LONG_PROP_WARN':None},
         res=_ok(md5='a364d8a262e8a12ddb7325b4f2555e2b', warnings=1, reg='allpass.reg'))

    Test('indivproptest_2.inf', glulx=True,
         res=_ok(md5='7e806bf207e3618424ad493ac7d187e7', warnings=0, reg='allpass.reg'))

    Test('indivproptest_2.inf', define={'LONG_PROP_WARN':None}, glulx=True,
         res=_ok(md5='7e806bf207e3618424ad493ac7d187e7', warnings=1, reg='allpass.reg'))

    Test('max_link_directive_length.inf',
         res=_error())

    Test('linkimport.inf',
         res=_ok())

    Test('linkimport.inf', define={'TRY_LINK':None},
         res=_error())

    Test('linkimport.inf', define={'TRY_IMPORT':None},
         res=_error())

    Test('globalarray.inf',
         res=_ok())

    Test('globalarray.inf', glulx=True,
         res=_ok())

    Test('globalarray.inf', define={'USE_GLOBAL_BEFORE_DEF':None},
         res=_error())

    Test('globalarray.inf', define={'DEFINE_GLOBAL_NONSYMBOL':None},
         res=_error())
    
    Test('globalarray.inf', define={'DEFINE_GLOBAL_STATIC':None},
         res=_error())
    
    Test('globalarray.inf', define={'DEFINE_GLOBAL_EXTRA':None},
         res=_error())
    
    Test('globalarray.inf', define={'DEFINE_GLOBAL_NOVALUE':None},
         res=_error())
    
    Test('globalarray.inf', define={'DEFINE_GLOBAL_ARRAY':None},
         res=_error())
    
    Test('globalarray.inf', define={'DEFINE_ARRAY_NO_DEF':None},
         res=_error())
    
    Test('globalarray.inf', define={'DEFINE_ARRAY_EXTRA':None},
         res=_error())
    
    Test('globalredef.inf',
         res=_ok())

    Test('globalredef.inf', glulx=True,
         res=_ok())

    Test('globalredef2.inf',
         res=_ok(reg='allpass.reg'))

    Test('globalredef2.inf', glulx=True,
         res=_ok(reg='allpass.reg'))

    Test('globalredef2.inf', define={'DEFINE_GLOBX1_NUM':None},
         res=_error())
    
    Test('globalredef2.inf', define={'DEFINE_GLOBX1_NUM':None}, glulx=True,
         res=_error())
    
    Test('globalredef2.inf', define={'DEFINE_GLOBX2_NUM':None},
         res=_error())
    
    Test('globalredef2.inf', define={'DEFINE_GLOBX2_NUM':None}, glulx=True,
         res=_error())
    
    Test('globalredef2.inf', define={'DEFINE_GLOBX2_NUM99':None},
         res=_error())
    
    Test('globalredef2.inf', define={'DEFINE_GLOBX2_NUM99':None}, glulx=True,
         res=_error())
    
    Test('unterm-array-test.inf',
         res=_error(errors=2))


class Run_Veneer(TestGroup, key='VENEER'):
    Test('obj_prop_call.inf',
         res=_ok())
    
    Test('obj_prop_call.inf', zversion=3,
         res=_error())
    
    Test('obj_prop_call.inf', zversion=3, define={'REPLACE_TWO':None},
         res=_ok())

    Test('base_class_prop.inf', zversion=3, includedir='punylib-36',
         res=_ok(md5='86c83ed4829f5c4e53e6685fa927b151', reg='base_class_prop.reg'))
    
    Test('base_class_prop.inf', zversion=5, includedir='punylib-36',
         res=_ok(md5='8c3cd775761a405f084ca7ac49780e87', reg='base_class_prop.reg'))
    
    Test('base_class_prop_2.inf', zversion=3, includedir='punylib-36',
         res=_ok(md5='e5dc2ee9206ab9ecc0e001b28dd8a581', reg='base_class_prop_2.reg'))
    
    Test('base_class_prop_2.inf', zversion=5, includedir='punylib-36',
         res=_ok(md5='f53971b601da7d05ae6f069fbe09c871', reg='base_class_prop_2.reg'))
    
    Test('obj_prop_test.inf',
         res=_ok(md5='2198d66552572a5283b2db6665e4fae6', reg='obj_prop_test-z.reg'))
    
    Test('obj_prop_test.inf', strict=False,
         res=_ok(md5='5ab9590d784d4baddb63ac69cd230bbf', reg='obj_prop_test-z.reg'))
    
    Test('obj_prop_test.inf', zversion=3,
         res=_ok(md5='4272074bb380e35bbe56e48294003971', reg='obj_prop_test-z.reg'))
    
    Test('obj_prop_test.inf', glulx=True,
         res=_ok(md5='fa5334982d7faf56cc42ea788c8e77cc', reg='obj_prop_test-g.reg'))
    
    Test('obj_prop_test.inf', glulx=True, strict=False,
         res=_ok(md5='6c6e6bcf3c2715b5f9962dd78e3adee3', reg='obj_prop_test-g.reg'))
    

class Run_Statements(TestGroup, key='STATEMENTS'):
    Test('switchcasetest.inf',
         res=_ok(reg='allpass.reg'))

    Test('switchcasetest.inf', glulx=True,
         res=_ok(reg='allpass.reg'))
    
    Test('switchcasetest.inf', define={'TOO_MANY_VALS_1':None},
         res=_memsetting('MAX_SPEC_STACK'))

    Test('switchcasetest.inf', define={'TOO_MANY_VALS_2':None},
         res=_memsetting('MAX_SPEC_STACK'))

    Test('switchcasetest.inf', glulx=True, define={'TOO_MANY_VALS_1':None},
         res=_memsetting('MAX_SPEC_STACK'))

    Test('switchcasetest.inf', glulx=True, define={'TOO_MANY_VALS_2':None},
         res=_memsetting('MAX_SPEC_STACK'))

    Test('switchcasetest.inf', define={'DEFAULT_BEFORE_CASE':None},
         res=_error())

    Test('switchcasetest.inf', glulx=True, define={'DEFAULT_BEFORE_CASE':None},
         res=_error())

    Test('switchcasetest.inf', define={'GLOB_VAR_CASE':None},
         res=_error())

    Test('switchcasetest.inf', define={'LOC_VAR_CASE':None},
         res=_error())

    Test('switchcasetest.inf', define={'FUNC_CALL_CASE':None},
         res=_error())

    Test('action_token_err.inf',
         res=_ok())

    Test('action_token_err.inf', define={'NUMBER_ACTION':None},
         res=_error())

    Test('action_token_err.inf', define={'STRING_ACTION':None},
         res=_error())

    Test('action_token_err.inf', define={'UNKNOWN_SYMBOL_ACTION':None},
         res=_error())

    Test('jumpopcodetest.inf',
         res=_ok(md5='386b0ef301175d6a5629adfacdcd1972', md5match='jumpopcodetest:z'))

    Test('jumpopcodetest.inf', define={'OPFORM':None},
         res=_ok(md5='386b0ef301175d6a5629adfacdcd1972', md5match='jumpopcodetest:z'))

    Test('jumpopcodetest.inf', glulx=True,
         res=_ok(md5='4286b36138e51806e5c955bc3c66ff94', md5match='jumpopcodetest:g'))

    Test('jumpopcodetest.inf', glulx=True, define={'OPFORM':None},
         res=_ok(md5='4286b36138e51806e5c955bc3c66ff94', md5match='jumpopcodetest:g'))

    Test('jumpbadtest.inf',
         res=_error())

    Test('jumpbadtest.inf', glulx=True,
         res=_error())

    Test('branchbadtest.inf',
         res=_error())

    Test('branchbadtest.inf', glulx=True,
         res=_error())


class Run_Expressions(TestGroup, key='EXPRESSIONS'):
    Test('unaryop_err_test.inf',
         res=_ok(md5='938b3674a095c3db4e8ec9de3cc65c3c', reg='allpass.reg'))

    Test('unaryop_err_test.inf', glulx=True,
         res=_ok(md5='92cf289c108ffb48be16e3aa69be9956', reg='allpass.reg'))

    Test('unaryop_err_test.inf', define={'BAD_EXPR_0':None},
         res=_error(errors=1))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_1':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_2':None},
         res=_error(errors=1))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_3':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_4':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_5':None},
         res=_error(errors=1))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_6':None},
         res=_error(errors=1))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_7':None},
         res=_error(errors=1))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_8':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_9':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_10':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_11':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_12':None},
         res=_error(errors=3))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_13':None},
         res=_error(errors=2))
    
    Test('unaryop_err_test.inf', define={'BAD_EXPR_14':None},
         res=_error(errors=2))
    
    Test('randomfunc.inf',
         res=_ok(md5='f0605e4ca2b9319202f69ad60f711175'))

    Test('randomfunc.inf', glulx=True,
         res=_ok(md5='de075fc5d37611be364d0772ee082ec5'))

    Test('sysfunc.inf',
         res=_ok(md5='d757c98bac4f194b83897754d0710ed5', reg='allpass.reg'))

    Test('sysfunc.inf', glulx=True,
         res=_ok(md5='0ae529afa2f30bde9bce6b20bcbb277c', reg='allpass.reg'))

    Test('sysfunc.inf', strict=False,
         res=_ok(md5='a7b52b44fbb8a1d3b596eea1d1ca89a1', reg='allpass.reg'))

    Test('sysfunc.inf', glulx=True, strict=False,
         res=_ok(md5='8072699b6e1d28b723593667fc4be90a', reg='allpass.reg'))

    # non-strict because we're testing low-level prop opcodes
    Test('prop_store_optim.inf', strict=False,
         res=_ok(md5='da82bc142be965aa60e7a352728b514d', reg='allpass.reg'))
    
    Test('prop_store_optim.inf', strict=False, glulx=True,
         res=_ok(md5='14efea1ea6f04af863bed183ba33989f', reg='allpass.reg'))
    

class Run_DebugFlag(TestGroup, key='DEBUGFLAG'):
    Test('no_debug_flag_test.inf',
         res=_ok(warnings=0))

    Test('no_debug_flag_test.inf', debug=True, strict=False,
         res=_error(warnings=1))

    Test('no_debug_flag_test.inf', debug=True,
         res=_error(warnings=1))

    Test('no_debug_flag_test.inf', glulx=True,
         res=_ok(warnings=0))

    # This case succeeds in Glulx because there's no INFIX code in the veneer.
    Test('no_debug_flag_test.inf', debug=True, strict=False, glulx=True,
         res=_ok(warnings=0))

    Test('no_debug_flag_test.inf', debug=True, glulx=True,
         res=_error(warnings=1))


class Run_AssemBytes(TestGroup, key='ASSEMBYTES'):
    Test('assembytes_test.inf',
         res=_ok(reg='allpass.reg'))

    Test('assembytes_test.inf', define={ 'BADFUNC_1':None },
         res=_error())

    Test('assembytes_test.inf', define={ 'BADFUNC_2':None },
         res=_error())

    Test('assembytes_test.inf', define={ 'BADFUNC_3':None },
         res=_error())

    Test('assembytes_test.inf', glulx=True,
         res=_ok(reg='allpass.reg'))

    Test('assembytes_test.inf', define={ 'BADFUNC_1':None }, glulx=True,
         res=_error())

    Test('assembytes_test.inf', define={ 'BADFUNC_2':None }, glulx=True,
         res=_error())

    Test('assembytes_test.inf', define={ 'BADFUNC_3':None }, glulx=True,
         res=_error())
    
    
class Run_Prune(TestGroup, key='PRUNE'):
    Test('branchprune.inf',
         res=_ok(md5='640bbfe85c29c2da2a46ea5fa0dae820', reg='allpass.reg'))

    Test('branchprune.inf', glulx=True,
         res=_ok(md5='acf2fe351129855c4962e3b625cde3f7', reg='allpass.reg'))

    Test('branchprune.inf', define={ 'BAD_JUMPS':None },
         res=_error())

    Test('branchprune.inf', define={ 'BAD_JUMPS':None }, glulx=True,
         res=_error())

    Test('branchprune.inf', define={ 'BAD_JUMPS':None }, memsettings={'STRIP_UNREACHABLE_LABELS':0 },
         res=_ok(md5='b62272944513029b7b2238324f16e92c', reg='allpass.reg'))

    Test('branchprune.inf', define={ 'BAD_JUMPS':None }, memsettings={'STRIP_UNREACHABLE_LABELS':0 }, glulx=True,
         res=_ok(md5='73f2f9dd957cb4d62b0dfaa698681c1e', reg='allpass.reg'))

    Test('branchprune-fwd.inf',
         res=_ok(md5='38d1e28c12349b24a01f7c3d2d449b04', warnings=1, reg='allpass.reg'))

    Test('branchprune-fwd.inf', glulx=True,
         res=_ok(md5='9c48ebcfe754389a50c80c54ee780eb1', warnings=1, reg='allpass.reg'))

    Test('branchprune-nowarn.inf',
         res=_ok(md5='a961b02b9c344d957d2a4fd482da0464', md5match='branchprune-nowarn:z:strip', warnings=0))

    Test('branchprune-nowarn.inf', glulx=True,
         res=_ok(md5='170eae8487d1ce20b88de8beee1f9d5c', md5match='branchprune-nowarn:z', warnings=0))

    Test('branchprune-nowarn.inf', memsettings={'STRIP_UNREACHABLE_LABELS':0 },
         res=_ok(md5='a961b02b9c344d957d2a4fd482da0464', md5match='branchprune-nowarn:z:strip', warnings=0))

    Test('branchprune-nowarn.inf', memsettings={'STRIP_UNREACHABLE_LABELS':0 }, glulx=True,
         res=_ok(md5='170eae8487d1ce20b88de8beee1f9d5c', md5match='branchprune-nowarn:z', warnings=0))

    Test('logicprune.inf',
         res=_ok(md5='d73bdb9bda770c53a02e3267f41da5fa', warnings=0, reg='allpass.reg'))

    Test('logicprune.inf', glulx=True,
         res=_ok(md5='e33841ca3794d30b24265ec70311e53b', warnings=0, reg='allpass.reg'))

    Test('branchreduce.inf',
         res=_ok(md5='bbcd17f392625253c78a8881bac889ef', warnings=0, reg='allpass.reg'))
    
    Test('branchreduce.inf', strict=False,
         res=_ok(md5='9c5fc52444df6b9a1ecac3ca64706a97', warnings=0, reg='allpass.reg'))
    
    Test('branchreduce.inf', zversion=3,
         res=_ok(md5='2b4f2b5791c8d769fa03bfacc1492d37', warnings=0, reg='allpass.reg'))
    

    Test('branchcorner.inf',
         res=_ok(md5='4170709824bbed654c041f5a05f3a945', warnings=0, reg='allpass.reg'))
    
    Test('branchcorner.inf', strict=False,
         res=_ok(md5='6c12853be8766fc650ee0e4877c4bba2', warnings=0, reg='allpass.reg'))
    
    Test('branchcorner.inf', glulx=True,
         res=_ok(md5='89504beb6a64f3ebdaeb8881402f5a30', warnings=0, reg='allpass.reg'))
    
    
    Test('tasksacktest.inf', includedir='i6lib-611',
         res=_ok(md5='ff52c6a0db218aa7f0b1ae766bcf88bf', reg='tasksacktest.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_TASKS':None },
         res=_ok(md5='191c0aede67c44dc0d526f6ab73d526a', reg='tasksacktest-t.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None },
         res=_ok(md5='91df209cf3575200110b2efaf13c5987', reg='tasksacktest-s.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None, 'COMPILE_TASKS':None },
         res=_ok(md5='ce1c36996130d2b85e5e9ff41824ca50', reg='tasksacktest-st.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='db854286b0c5580ebaeea4f605b63db1', reg='tasksacktest.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_TASKS':None }, glulx=True,
         res=_ok(md5='6c469f61037ddf09ba701cedd18f69d5', reg='tasksacktest-t.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None }, glulx=True,
         res=_ok(md5='1ac647839b26706e615aa15ccc985b53', reg='tasksacktest-s.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None, 'COMPILE_TASKS':None }, glulx=True,
         res=_ok(md5='74176ff2736cc48596a0228da91f36f4', reg='tasksacktest-st.reg'))


class Run_CompileOpt(TestGroup, key='COMPILEOPT'):
    # Can't change DICT_WORD_SIZE in Z-code
    Test('optprectest.inf',
         res=_error())
    
    Test('optprectest.inf', glulx=True,
         res=_ok(md5='7831b6cb6074561cebdc77e53b8af245'))
    
    Test('optprectest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':12},
         res=_ok(md5='a29eaf8cad45a33c9753236944f229b1'))
    
    Test('optprectest.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':19},
         res=_ok(md5='6e13e68df5b9d02b0d1200bf8df301a0'))
    
    Test('optprectest.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':19, 'DICT_WORD_SIZE':12},
         res=_ok(md5='08f73f6698bc2c4329d5c1b1f472b93a'))
    
    
class Run_DefineOpt(TestGroup, key='DEFINEOPT'):
    Test('defineopttest.inf',
         res=_ok(md5='58112116f921467096c62f4213a1d3ab'))

    Test('defineopttest.inf', debug=True,
         res=_ok(md5='3c61dba266b659b85c282c9fa2ef21a2'))

    Test('defineopttest.inf', define={ 'DEBUG':None },
         res=_ok(md5='3c61dba266b659b85c282c9fa2ef21a2'))

    Test('defineopttest.inf', define={ 'DEBUG':0 },
         res=_ok(md5='3c61dba266b659b85c282c9fa2ef21a2'))

    Test('defineopttest.inf', define={ 'FOO':26, 'BAR':-923, 'BAZ':None, 'QUUX':123, 'MUM':-1, 'NERTZ':99999 },
         res=_ok(md5='e36e11c8dc8b0da2e390fea5ce55699f'))

    # Can't redefine a compiler constant
    Test('defineopttest.inf', define={ 'WORDSIZE':3 },
         res=_error())

    # Symbols are case-insensitive
    Test('defineopttest.inf', define={ 'Wordsize':4 },
         res=_error())

    # Can't redefine a global or other symbol type either
    Test('defineopttest.inf', define={ 'sw__var':None },
         res=_error())

    Test('defineopttest.inf', define={ 'name':1 },
         res=_error())

    # Can't define the same constant twice (symbols are case-insensitive!)
    Test('defineopttest.inf', define={ 'XFOO':1, 'xfoo':2 },
         res=_error())

    # Redefining a constant to the same value is ok
    Test('defineopttest.inf', define={ 'WORDSIZE':2 },
         res=_ok(md5='58112116f921467096c62f4213a1d3ab'))

    Test('defineopttest.inf', define={ 'XFOO':3, 'xfoo':3 },
         res=_ok(md5='58112116f921467096c62f4213a1d3ab'))

    Test('defineopttest.inf', glulx=True,
         res=_ok(md5='333fe8a75515113435491c94d3d6e57f'))

    Test('defineopttest.inf', glulx=True, debug=True,
         res=_ok(md5='e2edd7ab2c5a51cbcc998ea76a2bfcb1'))

    Test('defineopttest.inf', glulx=True, define={ 'DEBUG':None },
         res=_ok(md5='e2edd7ab2c5a51cbcc998ea76a2bfcb1'))

    Test('defineopttest.inf', glulx=True, define={ 'DEBUG':0 },
         res=_ok(md5='e2edd7ab2c5a51cbcc998ea76a2bfcb1'))

    Test('defineopttest.inf', glulx=True, define={ 'Wordsize':4 },
         res=_ok(md5='333fe8a75515113435491c94d3d6e57f'))


class Run_FwConst(TestGroup, key='FWCONST'):
    Test('fwconst_release_test.inf',
         res=_error())

    Test('fwconst_release_test.inf', define={ 'FORWARD_CONSTANT':7 },
         res=_ok())

    Test('fwconst_release_test.inf', glulx=True,
         res=_error())

    Test('fwconst_release_test.inf', define={ 'FORWARD_CONSTANT':7 }, glulx=True,
         res=_ok())

    Test('fwconst_version_test.inf', destfile='fwconst_version_test.z5',
         res=_error())

    Test('fwconst_version_test.inf', destfile='fwconst_version_test.z3', define={ 'FORWARD_CONSTANT':3 },
         res=_ok(md5='e8b044eaef2b489db9ab0a1cc0f2bc5f'))

    Test('fwconst_version_test.inf', destfile='fwconst_version_test.z5', define={ 'FORWARD_CONSTANT':5 },
         res=_ok(md5='90866a483312a4359bc00db776e6eed4', md5match='minimal_test:z'))

    Test('fwconst_version_test.inf', destfile='fwconst_version_test.z8', define={ 'FORWARD_CONSTANT':8 },
         res=_ok(md5='fa7fc9bbe032d27355b0fcf4fb4f2c53'))

    Test('fwconst_version_test.inf', destfile='fwconst_version_test.z9', define={ 'FORWARD_CONSTANT':9 },
         res=_error())

    Test('fwconst_dictionary_test.inf',
         res=_error())

    Test('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1 },
         res=_error())

    Test('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_B':2 },
         res=_error())

    Test('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1, 'FORWARD_CONSTANT_B':2 },
         res=_ok())

    Test('fwconst_dictionary_test.inf', glulx=True,
         res=_error())

    Test('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1 }, glulx=True,
         res=_error())

    Test('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_B':2 }, glulx=True,
         res=_error())

    Test('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1, 'FORWARD_CONSTANT_B':2 }, glulx=True,
         res=_ok())

    Test('fwconst_iftrue_test.inf',
         res=_error())

    Test('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':1 },
         res=_error())

    Test('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_B':1 },
         res=_error())

    Test('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':1, 'FORWARD_CONSTANT_B':1 },
         res=_ok())

    Test('fwconst_iftrue_test.inf', glulx=True,
         res=_error())

    Test('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':0 }, glulx=True,
         res=_error())

    Test('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_B':0 }, glulx=True,
         res=_error())

    Test('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':0, 'FORWARD_CONSTANT_B':0 }, glulx=True,
         res=_ok())


class Run_DebugFile(TestGroup, key='DEBUGFILE'):
    Test('Advent.inf', includedir='i6lib-611', debugfile=True,
         res=_ok(md5='4b60c92f0e1d0b7735a6b237b1b99733', md5match='Advent:z', warnings=0, debugfile='a3d2311173164759356b6066a8f748c9'))

    Test('Advent.inf', includedir='i6lib-611', debugfile=True, glulx=True,
         res=_ok(md5='6ba4eeca5bf7834488216bcc1f62586c', md5match='Advent:g', warnings=0, debugfile='b303432b1da9b195813d851260a9f886'))

    Test('Advent.inf', includedir='i6lib-611', debugfile=True, memsettings={'OMIT_SYMBOL_TABLE':1},
         res=_ok(md5='ecf5622e340ac49276f0acfcc1b03279', warnings=0, debugfile='9959112940a9d05d082e0aec4c615030'))

    Test('Advent.inf', includedir='i6lib-611', debugfile=True, memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='f9c856a53a5f0a825c8baa182a4035d1', warnings=0, debugfile='654a95c08a946599d0e54a629cf19cff'))


class Run_Warnings(TestGroup, key='WARNINGS'):
    Test('typewarningtest.inf',
         res=_ok(warnings=83))
    
    Test('typewarningtest.inf', glulx=True,
         res=_ok(warnings=85))
    
    Test('callwarningtest.inf',
         res=_ok(warnings=61))
    
    Test('callwarningtest.inf', glulx=True,
         res=_ok(warnings=62))
    
    Test('or_warnings_test.inf',
         res=_ok(warnings=11))
    
    Test('or_warnings_test.inf', glulx=True,
         res=_ok(warnings=11))
    
    Test('or_condition_test.inf',
         res=_ok(md5='6bd242739f06667e5e0df910618846ba', warnings=4, reg='allpass.reg'))

    Test('or_condition_test.inf', glulx=True,
         res=_ok(md5='34cbc765cb174293b06b97d3bdbc8258', warnings=4, reg='allpass.reg'))


class Run_Trace(TestGroup, key='TRACE'):
    Test('Advent.inf', includedir='i6lib-611', trace={ 'ACTIONS':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'ASM':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'ASM':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'ASM':3 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'ASM':4 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'BPATCH':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'BPATCH':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'DICT':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'DICT':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'EXPR':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'EXPR':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'EXPR':3 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'FILES':1 },
         res=_ok())

    Test('abbrevtest.inf', makeabbrevs=True, trace={ 'FINDABBREVS':1 },
         res=_ok())
    
    Test('abbrevtest.inf', makeabbrevs=True, trace={ 'FINDABBREVS':2 },
         res=_ok())
    
    Test('abbrevtest.inf', economy=True, trace={ 'FREQ':1 },
         res=_ok())
    
    Test('Advent.inf', includedir='i6lib-611', trace={ 'MAP':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'MAP':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'MEM':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'OBJECTS':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'PROPS':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'STATS':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'SYMBOLS':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'SYMDEF':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'SYMBOLS':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'TOKENS':1 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'TOKENS':2 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'TOKENS':3 },
         res=_ok())

    Test('Advent.inf', includedir='i6lib-611', trace={ 'VERBS':1 },
         res=_ok())


class Run_Abbreviations(TestGroup, key='ABBREVIATIONS'):
    Test('max_abbrev_len_test.inf',
         res=_ok(warnings=0))
    
    Test('short_abbrevs_test.inf', economy=True,
         res=_ok(warnings=4))

    Test('symbolic_abbrev_test.inf',
         res=_ok(reg='allpass.reg'))

    Test('symbolic_abbrev_test.inf', glulx=True,
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':102}, glulx=True,
         res=_ok(reg='allpass.reg'))

    Test('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':0},
         res=_error())

    Test('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':0}, glulx=True,
         res=_error())

    Test('symbolic_abbrev_test.inf', define={'BADSYNTAX':None},
         res=_error(errors=8))

    Test('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':102}, define={'BADSYNTAX':None}, glulx=True,
         res=_error(errors=8))

    Test('nested_abbrev_test.inf',
         res=_ok(warnings=0))

    Test('nested_abbrev_test.inf', economy=True,
         res=_ok(warnings=1))

    Test('nested_abbrev_test.inf', glulx=True, economy=True,
         res=_ok(warnings=0))

    Test('nested_lowstring_test.inf',
         res=_ok(warnings=1))

    
    
class Run_Make_Abbreviations(TestGroup, key='MAKE_ABBREVIATIONS'):
    Test('abbrevtest.inf', makeabbrevs=True, economy=True,
         res=_ok(abbreviations=['. ', ', ', '**]', "='@", ' the', 'tried to print (', 'string', 'objec', ' on something n', ' here', ' tha', "31'.^", 'ing', ' to ', 'tribute', '~ o', 'lass', 'ate', 'ther', 'which', 'for', ': 0', "16'", 'ave', 'loop', 'can', 'mber', 'tion', 'is n', 'cre', 'use', 'ed ', 'at ', 'or ', 'ot ', 'has', "00'", "01'", '-- ', 'est', 'er ', 'hall ', 'is ', 'in ', 'we ', 'ead', 'of ', 'out', 'rem', ' a ', 'not', 'nse', 'ove', ' de', ' to', ' it', ' wh', ' us', 'se ', 'de '], warnings=11))

    Test('long_abbrevtest.inf', makeabbrevs=True, economy=True,
         res=_ok(abbreviations=['. ', ', ', 'This ', 'is a long string the likes of which may not have been seen in the text -- ']))

    Test('longer_abbrevtest.inf', makeabbrevs=True, economy=True,
         res=_ok(abbreviations=['. ', ', ', 'This ', 'is a long string the likes of which may not have been seen in the text on a Tuesday in April with the sun shining and elephants fluttering by; oh have you considered the song of the elephants; there is nothing like it -- ']))

    Test('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True,
         res=_ok(abbreviations=['. ', ', ', 'You ', "'t ", 'ing ', '**]', 'The', 'That', 'you can', 'someth', '_to)', 'closed', 're ', 'bject', 'already ', 'But ', 's no', 'which ', ' to ', 'ing', 'can', "You'", 'ome', 'the', 'your', 'Command', 't of', 'achieve', 'Language', 'scrip', 'have', 'tion', 'ou aren', 'seem', 'nd ', 'you', 'at ', 'noth', 'see ', 'ose ', 'ed.', 'of ', 'ed ', 'ch ', 'ect', 'not ', 'Not', 'in ', 'read', 'would ', 'on ', 'You', 'ere.', 'int', 'provid', 'est', 'empt', 'lock', '~ or ', 'ight', 'is ', 've ', 'me ', 'first']))

    Test('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':2},
         res=_ok(abbreviations=['. ', ', ']))

    Test('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':10},
         res=_ok(abbreviations=['. ', ', ', 'You ', "'t ", 'ing ', '**]', ' th', 'ou can', 'The', 'That']))

    Test('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':20},
         res=_ok(abbreviations=['. ', ', ', 'You ', '\'t ', 'ing ', '**]', 'The', 'That', 'you can', 'someth', ' th', ' you', ' on', 'ing', 'can', ' not', ' ha', ' of', ' seem', 'You\'']))

    Test('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':96},
         res=_ok(abbreviations=['. ', ', ', 'You ', '\'t ', 'ing ', '**]', 'The', 'That', 'you can', 'someth', '_to)', 're ', 'closed', 'bject', 'But ', 's no', 'already ', 'which ', 'Command', 'script', ' to ', 'ing', 'can', 'You\'', 'ome', 'tion', 'the', 'your', 't of', 'achieve', 'Language', 'have', 'ou aren', 'Those', 'ou wan', 'this', 'provid', 'would', 'ter', 'unexpected', 'lock', 'nd ', 'you', 'at ', 'noth', 'of ', 'ed.', 'ed ', 'se ', 'ch ', 'is ', 'Not', 'not ', 'in ', 'seem', 'read', 'on ', 'You', 'ere.', 'est', 'er ', '~ or ', 'ight', 'first', 'int', 've ', 'see ', 'as ', 'ly ', 'ide ', 'ect', 'put ', 'en ', 'an ', 'lass ', 'ns ', 'record', 'It ', 'ent', '\'s ', 'off ', 'get ', 'nce ', 'I d', 'ort', 'le.', 'be ', 'wit', 'le ', 'ious ', 'gam', 'n\'t', 'off.', 'on.', ' th', ' on']))

    
class Run_Max_Ifdef_Stack(TestGroup, key='MAX_IFDEF_STACK'):
    # Fixed limit; no memory setting to change.
    
    Test('max_ifdef_stack_32.inf',
         res=_ok())

    Test('max_ifdef_stack_33.inf',
         res=_memsetting('MAX_IFDEF_STACK'))

class Run_Max_Switch_Case_Values(TestGroup, key='MAX_SWITCH_CASE_VALUES'):
    # Fixed limit

    Test('max_switch_case_values.inf',
         res=_ok())

    Test('max_switch_case_values.inf', define={ 'SWITCH_ERROR':0 },
         res=_memsetting('MAX_SPEC_STACK'))

    
class Run_Max_Inclusion_Depth(TestGroup, key='MAX_INCLUSION_DEPTH'):
    Test('max_inclusion_depth_test.inf', includedir='src/include',
         res=_ok())
    
    Test('max_inclusion_depth_test.inf', includedir='src/include', glulx=True,
         res=_ok())


class Run_Max_Source_Files(TestGroup, key='MAX_SOURCE_FILES'):
    Test('max_source_files_test.inf', includedir='src/include',
         res=_ok())
    
    Test('max_origsource_direct_test.inf',
         res=_ok())
    

class Run_Max_Unicode_Chars(TestGroup, key='MAX_UNICODE_CHARS'):
    Test('max_unicode_chars_test.inf', glulx=True,
         res=_ok())

    
class Run_Max_Symbols(TestGroup, key='MAX_SYMBOLS'):
    Test('max_symbols_test.inf',
         res=_ok())
    
    Test('max_symbols_test.inf', glulx=True,
         res=_ok())


class Run_Symbols_Chunk_Size(TestGroup, key='SYMBOLS_CHUNK_SIZE'):
    Test('max_symbols_test.inf',
         res=_ok())
    
    Test('max_symbols_test.inf', glulx=True,
         res=_ok())


class Run_Max_Objects(TestGroup, key='MAX_OBJECTS'):
    Test('max_objects_test.inf',
         res=_ok())

    Test('max_objects_test.inf', glulx=True,
         res=_ok())

    Test('max_objects_256_test.inf', zversion=3,
         res=_ok())

    Test('max_objects_256_test.inf', zversion=3, define={ 'ONEMORE':0 },
         res=_error())

    Test('max_objects_256_test.inf', zversion=4,
         res=_ok())

    Test('max_objects_256_test.inf', zversion=4, define={ 'ONEMORE':0 },
         res=_ok())

    Test('max_objects_256_test.inf', zversion=5,
         res=_ok())

    Test('max_objects_256_test.inf', zversion=5, define={ 'ONEMORE':0 },
         res=_ok())

    Test('max_duplicate_objects_test.inf', glulx=True,
         res=_ok())


class Run_Max_Classes(TestGroup, key='MAX_CLASSES'):
    Test('max_classes_test.inf',
         res=_ok())

    Test('max_classes_test.inf', glulx=True,
         res=_ok())

    Test('max_classes_256_test.inf', zversion=3,
         res=_ok())

    Test('max_classes_256_test.inf', zversion=3, define={ 'ONEMORE':0 },
         res=_error())

    Test('max_classes_256_test.inf', zversion=4,
         res=_ok())

    Test('max_classes_256_test.inf', zversion=4, define={ 'ONEMORE':0 },
         res=_ok())

    Test('max_classes_256_test.inf', zversion=5,
         res=_ok())

    Test('max_classes_256_test.inf', zversion=5, define={ 'ONEMORE':0 },
         res=_ok())


class Run_Max_Arrays(TestGroup, key='MAX_ARRAYS'):
    Test('max_arrays_test.inf',
         res=_ok())

    Test('max_arrays_test.inf', glulx=True,
         res=_ok())

    Test('max_arrays_test_2.inf',
         res=_ok())

    Test('max_arrays_test_2.inf', glulx=True,
         res=_ok())

    Test('max_arrays_test_3.inf',
         res=_ok())

    Test('max_arrays_test_3.inf', glulx=True,
         res=_ok())


class Run_Max_Attr_Bytes(TestGroup, key='MAX_ATTR_BYTES'):
    Test('max_attributes.inf',
         res=_memsetting('MAX_ATTRIBUTES'))
    
    Test('max_attributes.inf', glulx=True,
         res=_memsetting('MAX_ATTRIBUTES'))
    
    Test('max_attributes.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':11},
         res=_ok())
    

class Run_Max_Prop_Table_Size(TestGroup, key='MAX_PROP_TABLE_SIZE'):
    Test('max_prop_table_size_test.inf',
         res=_ok())

    Test('max_prop_table_size_test.inf', glulx=True,
         res=_ok())

    # Glulx uses this setting for individual properties too

    Test('max_indiv_prop_table_size_test.inf', glulx=True,
         res=_ok())

    # A single large object can run into this setting too.
    
    Test('max_obj_prop_table_size_test.inf', glulx=True,
         res=_ok())

    # So can a Z-code object's shortname.

    Test('large_object_short_name_test.inf',
         res=_ok())

    Test('large_object_short_name_test_2.inf',
         res=_memsetting('MAX_SHORT_NAME_LENGTH'))


class Run_Max_Common_Prop_Count(TestGroup, key='MAX_COMMON_PROP_COUNT'):
    Test('max_common_props_test.inf',
         res=_memsetting('MAX_COMMON_PROPS'))

    Test('max_common_props_test.inf', zversion=3,
         res=_memsetting('MAX_COMMON_PROPS'))

    Test('max_common_props_test.inf', glulx=True,
         res=_ok())

    Test('max_common_props_test_280.inf', glulx=True,
         res=_memsetting('MAX_COMMON_PROPS'))

    Test('max_common_props_test_280.inf', memsettings={'INDIV_PROP_START':283}, glulx=True,
         res=_memsetting('MAX_COMMON_PROPS'))

    Test('max_common_props_test_280.inf', memsettings={'INDIV_PROP_START':284}, glulx=True,
         res=_ok())

    Test('common_props_plus_test.inf',
         res=_ok())

    Test('common_props_plus_test.inf', define={ 'TOOMANY':0 },
         res=_memsetting('MAX_COMMON_PROPS'))


class Run_Max_Common_Prop_Size(TestGroup, key='MAX_COMMON_PROP_SIZE'):
    Test('max_prop_size_test.inf', define={ 'MAX_COMMON_PROP':0 },
         res=_ok())
    
    Test('max_prop_size_test.inf', define={ 'TOOBIG_COMMON_PROP':0 },
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('max_prop_size_test.inf', define={ 'MAX_ADDITIVE_PROP':0 },
         res=_ok())
    
    Test('max_prop_size_test.inf', define={ 'TOOBIG_ADDITIVE_PROP':0 },
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('max_prop_size_test.inf', zversion=3, define={ 'MAX_COMMON_PROP_V3':0 },
         res=_ok())
    
    Test('max_prop_size_test.inf', zversion=3, define={ 'TOOBIG_COMMON_PROP_V3':0 },
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('max_prop_size_test.inf', zversion=3, define={ 'MAX_ADDITIVE_PROP_V3':0 },
         res=_ok())
    
    Test('max_prop_size_test.inf', zversion=3, define={ 'TOOBIG_ADDITIVE_PROP_V3':0 },
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('max_prop_size_test.inf', define={ 'MAX_CLASSES':0 },
         res=_ok())
    
    Test('max_prop_size_test.inf', define={ 'TOOBIG_CLASSES':0 },
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('max_prop_size_test.inf', zversion=3, define={ 'MAX_CLASSES_V3':0 },
         res=_ok())
    
    Test('max_prop_size_test.inf', zversion=3, define={ 'TOOBIG_CLASSES_V3':0 },
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    
class Run_Max_Indiv_Prop_Table_Size(TestGroup, key='MAX_INDIV_PROP_TABLE_SIZE'):
    Test('max_indiv_prop_table_size_test.inf',
         res=_ok())

    # Glulx does not use this setting, so no Glulx tests.

    
class Run_Max_obj_Prop_Table_Size(TestGroup, key='MAX_OBJ_PROP_TABLE_SIZE'):
    Test('max_obj_prop_table_size_test.inf', glulx=True,
         res=_ok())


class Run_Max_Obj_Prop_Count(TestGroup, key='MAX_OBJ_PROP_COUNT'):
    Test('max_obj_prop_count_test.inf', glulx=True,
         res=_ok())

    Test('property_too_long.inf',
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('property_too_long.inf', glulx=True,
         res=_ok())
    
    Test('property_too_long_inherit.inf',
         res=_memsetting('MAX_PROP_LENGTH_ZCODE'))
    
    Test('property_too_long_inherit.inf', glulx=True,
         res=_ok())
    

class Run_Max_Global_Variables(TestGroup, key='MAX_GLOBAL_VARIABLES'):
    # In Z-code, at most 233 globals are available, and you can't raise the
    # limit.
    Test('max_global_variables_test.inf',
         res=_ok())
    
    Test('max_global_variables_test.inf', zversion=3,
         res=_ok())
    
    Test('max_global_variables_test.inf', define={ 'ONEMORE':0 },
         res=_memsetting('MAX_GLOBAL_VARIABLES'))
    
    Test('max_global_variables_test.inf', zversion=3, define={ 'ONEMORE':0 },
         res=_memsetting('MAX_GLOBAL_VARIABLES'))
    
    Test('max_global_variables_test_2.inf',
         res=_memsetting('MAX_GLOBAL_VARIABLES'))
    
    Test('max_global_variables_test_2.inf', glulx=True,
         res=_ok())


class Run_Max_Local_Variables(TestGroup, key='MAX_LOCAL_VARIABLES'):
    # In Z-code, at most 15 locals are available, and you can't raise the
    # limit. In Glulx, at most 118.
    
    Test('max_local_variables_test_15.inf',
         res=_ok())
    
    Test('max_local_variables_test_16.inf',
         res=_memsetting('MAX_LOCAL_VARIABLES'))

    Test('max_local_variables_test_16.inf', glulx=True,
         res=_ok())

    Test('max_local_variables_test_31.inf', glulx=True,
         res=_ok())

    Test('max_local_variables_test_32.inf', glulx=True,
         res=_ok())

    Test('max_local_variables_test_118.inf', glulx=True,
         res=_ok())

    Test('max_local_variables_test_119.inf', glulx=True,
         res=_memsetting('MAX_LOCAL_VARIABLES'))

    
class Run_Max_Static_Data(TestGroup, key='MAX_STATIC_DATA'):
    Test('max_static_data_test.inf',
         res=_ok())

    Test('max_static_data_test.inf', glulx=True,
         res=_ok())

    Test('max_static_data_test_2.inf',
         res=_ok())

    Test('max_static_data_test_2.inf', glulx=True,
         res=_ok())

    Test('max_static_data_test_3.inf',
         res=_ok())

    Test('max_static_data_test_3.inf', glulx=True,
         res=_ok())


class Run_Max_Num_Static_Strings(TestGroup, key='MAX_NUM_STATIC_STRINGS'):
    # Glulx only

    Test('static_text_test.inf', glulx=True,
         res=_ok())

    
class Run_Max_Qtext_Size(TestGroup, key='MAX_QTEXT_SIZE'):
    Test('max_static_strings_test.inf',
         res=_ok())

    Test('max_static_strings_test.inf', glulx=True,
         res=_ok())

    
class Run_Max_Static_Strings(TestGroup, key='MAX_STATIC_STRINGS'):
    # The compiler ensures that MAX_STATIC_STRINGS is (at least) twice
    # MAX_QTEXT_SIZE.
    
    Test('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001},
         res=_ok())

    Test('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001}, glulx=True,
         res=_ok())


class Run_Max_Low_Strings(TestGroup, key='MAX_LOW_STRINGS'):
    # Only meaningful for Z-code.
    
    Test('max_low_strings_test.inf',
         res=_ok())

    
class Run_Max_Dynamic_Strings(TestGroup, key='MAX_DYNAMIC_STRINGS'):
    Test('max_dynamic_strings_test_at15.inf', memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_at31.inf', memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_at32.inf', memsettings={},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at15.inf', glulx=True, memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_at31.inf', glulx=True, memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_at32.inf', glulx=True, memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_at63.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64},
         res=_ok())

    Test('max_dynamic_strings_test_at64.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_str31.inf', memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_str32.inf', memsettings={},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_str31.inf', glulx=True, memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_str32.inf', glulx=True, memsettings={},
         res=_ok())

    Test('max_dynamic_strings_test_str63.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64},
         res=_ok())

    Test('max_dynamic_strings_test_str64.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at32.inf', memsettings={'MAX_DYNAMIC_STRINGS':33},
         res=_ok())

    Test('max_dynamic_strings_test_at95.inf', memsettings={'MAX_DYNAMIC_STRINGS':95},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at95.inf', memsettings={'MAX_DYNAMIC_STRINGS':96},
         res=_ok())

    Test('max_dynamic_strings_test_str31.inf', memsettings={'MAX_ABBREVS':65},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at31.inf', memsettings={'MAX_ABBREVS':65},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at95.inf', memsettings={'MAX_ABBREVS':1},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at95.inf', memsettings={'MAX_ABBREVS':0},
         res=_ok())

    Test('max_dynamic_strings_test_str64.inf', memsettings={'MAX_ABBREVS':31},
         res=_ok())

    Test('max_dynamic_strings_test_str32.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':32},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at32.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':32},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_str64.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':65},
         res=_ok())

    Test('max_dynamic_strings_test_at99.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':99},
         res=_memsetting('MAX_DYNAMIC_STRINGS'))

    Test('max_dynamic_strings_test_at99.inf', glulx=True, memsettings={},
         res=_ok())

    
class Run_Max_Inline_String(TestGroup, key='MAX_INLINE_STRING'):
    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':64},
         res=_ok(md5='d3710d50851222471880bfe3eaf25105', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':800},
         res=_ok(md5='be385c96fd724aee2b1f845fe51a621f', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':10000},
         res=_ok(md5='be385c96fd724aee2b1f845fe51a621f', warnings=0, reg='Advent-z.reg'))

    Test('max_inline_string_test.inf',
         res=_ok(warnings=0))

    Test('max_inline_string_test.inf', memsettings={'ZCODE_MAX_INLINE_STRING':999},
         res=_ok(warnings=0))

    Test('max_inline_string_test.inf', memsettings={'ZCODE_MAX_INLINE_STRING':1000},
         res=_error())

    
    
class Run_Max_Abbrevs(TestGroup, key='MAX_ABBREVS'):
    Test('abbrevtest.inf',
         res=_ok(md5='d2dc7c61e2696aee6128df2851de87b9'))
    
    Test('abbrevtest.inf', glulx=True,
         res=_ok(md5='fa2130036715d5ec0f6b7e53a1f74e2c'))
    
    Test('abbrevtest.inf', economy=True,
         res=_ok(md5='86da9481371de892a33c2b43a8ca9151'))
    
    Test('abbrevtest.inf', glulx=True, economy=True,
         res=_ok(md5='774d0dd65eabbbc84a41aa1324f567c3'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611',
         res=_ok(md5='4b60c92f0e1d0b7735a6b237b1b99733', md5match='Advent:z'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='6ba4eeca5bf7834488216bcc1f62586c', md5match='Advent:g'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', economy=True,
         res=_ok(md5='603b390c1464bec7a4b88a548ebb4ff2'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', glulx=True, economy=True,
         res=_ok(md5='b74045fe8a5101805fc2e3a57fd03fed'))
    
    Test('i7-min-6G60-abbrev.inf', zversion=8, economy=True,
         res=_ok(md5='c0db8cc8edd8f9973e1d75222102be2f', reg='i7-min-6G60.reg'))
    
    Test('max_abbrevs_test_64.inf', economy=True, memsettings={},
         res=_ok())

    Test('max_abbrevs_test_64.inf', economy=True, memsettings={'MAX_ABBREVS':63},
         res=_memsetting('MAX_ABBREVS'))

    Test('max_abbrevs_test_32.inf', economy=True, memsettings={'MAX_ABBREVS':32},
         res=_ok())

    Test('max_abbrevs_test_32.inf', economy=True, memsettings={'MAX_ABBREVS':31},
         res=_memsetting('MAX_ABBREVS'))

    Test('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_ABBREVS':96},
         res=_ok())

    Test('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_ABBREVS':95},
         res=_memsetting('MAX_ABBREVS'))

    Test('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_DYNAMIC_STRINGS':0},
         res=_ok())

    Test('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_DYNAMIC_STRINGS':1},
         res=_memsetting('MAX_ABBREVS'))

    Test('max_abbrevs_test_100.inf', economy=True, memsettings={'MAX_ABBREVS':96},
         res=_memsetting('MAX_ABBREVS'))

    Test('max_abbrevs_test_64.inf', economy=True, glulx=True,
         res=_ok())

    Test('max_abbrevs_test_32.inf', economy=True, glulx=True,
         res=_ok())

    Test('max_abbrevs_test_96.inf', economy=True, glulx=True,
         res=_ok())

    Test('max_abbrevs_test_100.inf', economy=True, glulx=True,
         res=_ok())


class Run_Max_verb_word_size(TestGroup, key='MAX_VERB_WORD_SIZE'):
    # Fixed limit; no memory setting to change.
    
    Test('max_verb_word_size.inf',
         res=_ok())

    Test('max_verb_word_size_2.inf',
         res=_ok())
    
    Test('max_verb_word_size.inf', glulx=True,
         res=_ok())

    Test('max_verb_word_size_2.inf', glulx=True,
         res=_ok())


class Run_Max_lines_per_verb(TestGroup, key='MAX_LINES_PER_VERB'):
    Test('max_lines_per_verb_32.inf',
         res=_ok())

    Test('max_lines_per_verb_33.inf',
         res=_ok())

    Test('max_lines_per_verb_40.inf',
         res=_ok())

    Test('max_lines_per_verb_40.inf', glulx=True,
         res=_ok())

    Test('max_lines_per_verb_extfirst.inf',
         res=_ok())

    Test('max_lines_per_verb_extfirst.inf', glulx=True,
         res=_ok())

    Test('max_lines_per_verb_extlast.inf',
         res=_ok())

    Test('max_lines_per_verb_extlast.inf', glulx=True,
         res=_ok())

    
class Run_Max_linespace(TestGroup, key='MAX_LINESPACE'):
    Test('max_linespace_test.inf',
         res=_ok())

    
class Run_Max_verb_synonyms(TestGroup, key='MAX_VERB_SYNONYMS'):
    Test('max_verb_synonyms_32.inf',
         res=_ok())

    Test('max_verb_synonyms_33.inf',
         res=_ok())
    
    
class Run_Max_Verbs(TestGroup, key='MAX_VERBS'):
    Test('max_verbs.inf',
         res=_ok())
    
    Test('max_verbs.inf', glulx=True,
         res=_ok())
    
    Test('max_verbs_2.inf',
         res=_memsetting('MAX_VERBS_ZCODE'))
    
    Test('max_verbs_2.inf', glulx=True,
         res=_ok())
    
    Test('max_verbs_3.inf',
         res=_memsetting('MAX_VERBS_ZCODE'))
    
    Test('max_verbs_3.inf', glulx=True,
         res=_ok())
    
    
class Run_unused_verbs(TestGroup, key='UNUSED_VERBS'):
    Test('unused_verbs.inf',
         res=_ok(warnings=0))
    
    Test('unused_verbs.inf', define={ 'ONLYFOO':0 },
         res=_ok(warnings=0))
    
    Test('unused_verbs.inf', define={ 'ONLYFOOX':0 },
         res=_ok(warnings=0))
    
    Test('unused_verbs.inf', define={ 'ONLYFOO':0, 'ONLYFOOX':0 },
         res=_ok(warnings=1))
    
    Test('unused_verbs.inf', glulx=True,
         res=_ok(warnings=0))
    
    Test('unused_verbs.inf', define={ 'ONLYFOO':0, 'ONLYFOOX':0 }, glulx=True,
         res=_ok(warnings=1))
    
    Test('unused_verbs.inf', define={ 'ONLYFOO':0, 'ONLYZOGA':0 },
         res=_ok(warnings=0))
    
    Test('unused_verbs.inf', define={ 'ONLYZOG':0, 'ONLYZOGA':0 },
         res=_ok(warnings=1))
    
    Test('unused_verbs_lib.inf', includedir='i6lib-611',
         res=_ok(md5='e36ec428894a855b6e11216ded5acd4d', warnings=2, reg='unused_verbs_lib.reg'))
    
    Test('unused_verbs_lib.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='d5b4e881b69ecb1354f0752450513518', warnings=2, reg='unused_verbs_lib.reg'))
    
    
class Run_Max_actions(TestGroup, key='MAX_ACTIONS'):
    Test('max_actions.inf',
         res=_ok())

    Test('max_actions.inf', glulx=True,
         res=_ok())

    # Can't handle 400 actions in grammar version 1
    Test('max_actions.inf', define={ 'MAKE_400':0 },
         res=_error())

    Test('max_actions.inf', define={ 'MAKE_400':0 }, memsettings={ 'GRAMMAR_VERSION':2 },
         res=_ok())

    Test('max_actions.inf', glulx=True, define={ 'MAKE_400':0 },
         res=_ok())

    Test('max_actions.inf', glulx=True,
         res=_ok())

    Test('max_grammar_routines_test.inf',
         res=_ok())

    # Glulx uses Grammar__Version 2, so the grammar_token_routine table is not used.
    Test('max_grammar_routines_test.inf', glulx=True,
         res=_ok())

    
class Run_Max_adjectives(TestGroup, key='MAX_ADJECTIVES'):
    Test('max_adjectives.inf',
         res=_ok())

    # Glulx uses Grammar__Version 2, so adjectives are not used.
    Test('max_adjectives.inf', glulx=True,
         res=_ok())

    Test('max_adjectives_2.inf',
         res=_ok())

    Test('max_adjectives_2.inf', glulx=True,
         res=_ok())

    Test('max_adjectives_256.inf',
         res=_memsetting('MAX_PREPOSITIONS_GV1'))

    Test('max_adjectives_256.inf', define={ 'USE_GV2':0 },
         res=_ok())

    Test('max_adjectives_256.inf', glulx=True,
         res=_ok())

    
class Run_Max_expression_nodes(TestGroup, key='MAX_EXPRESSION_NODES'):
    Test('max_expression_nodes_test.inf',
         res=_ok())

    Test('max_expression_nodes_test.inf', glulx=True,
         res=_ok())

    Test('max_expression_nodes_test_2.inf',
         res=_ok())

    Test('max_expression_nodes_test_2.inf', glulx=True,
         res=_ok())

    Test('max_expression_nodes_test_3.inf',
         res=_ok())

    Test('max_expression_nodes_test_3.inf', glulx=True,
         res=_ok())


class Run_Max_labels(TestGroup, key='MAX_LABELS'):
    Test('max_labels_test.inf',
         res=_ok())
    
    Test('max_labels_test.inf', glulx=True,
         res=_ok())


class Run_Max_zcode_size(TestGroup, key='MAX_ZCODE_SIZE'):
    Test('large_opcode_text_test.inf', memsettings={'MAX_QTEXT_SIZE':8001},
         res=_ok())

    Test('max_zcode_size_test.inf',
         res=_ok())

    Test('max_zcode_size_test.inf', glulx=True,
         res=_ok())

    Test('zcode_v3_overflow.inf', zversion=3,
         res=_error())

    Test('zcode_v3_overflow.inf',
         res=_ok())

    Test('zcode_v3_overflow.inf', glulx=True,
         res=_ok())


class Run_Omit_Unused_Routines(TestGroup, key='OMIT_UNUSED_ROUTINES'):
    Test('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='8021f52ee8b50848d6dda8bfa62b2aea', reg='i7-min-6G60.reg'))

    Test('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True,
         res=_ok(md5='2468b145e1d809d180f47dc21233e9d3', reg='i7-min-6G60.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='b6438b60907fa01bad2d1e50f2f8f22c', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True,
         res=_ok(md5='5c4e12640123585c013351a883b01c40', warnings=0, reg='Advent-g.reg'))

    Test('strip_func_test.inf', memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='07bd8dcf2c8f3a8e544a53584e417ad2'))

    Test('strip_func_test.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True,
         res=_ok(md5='5ebeba63f77407fc175f00055f565933'))


class Run_Omit_Symbol_Table(TestGroup, key='OMIT_SYMBOL_TABLE'):
    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_SYMBOL_TABLE':1},
         res=_ok(md5='ecf5622e340ac49276f0acfcc1b03279', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_SYMBOL_TABLE':1}, glulx=True,
         res=_ok(md5='6ddd65bd86cc1c3b6e172189c4831ef1', warnings=0, reg='Advent-g.reg'))

    Test('library_of_horror-36.inf', includedir='punylib-36', memsettings={'OMIT_SYMBOL_TABLE':1}, zversion=3,
         res=_ok(md5='2ec9bc48b11c34c714d96d7e5e931859', reg='library_of_horror.reg'))
    
    Test('omit-symbol-table-test.inf', memsettings={'OMIT_SYMBOL_TABLE':1},
         res=_ok(md5='cba5fee8cbc2ada303802386af3793e3', warnings=0))

    Test('omit-symbol-table-test.inf', memsettings={'OMIT_SYMBOL_TABLE':1}, glulx=True,
         res=_ok(md5='c674e8217a693124dfd0404fbe9b36dc', warnings=0))

    
class Run_ZCode_File_End_Padding(TestGroup, key='ZCODE_FILE_END_PADDING'):
    Test('minimal_test.inf', memsettings={'ZCODE_FILE_END_PADDING':0},
         res=_ok(md5='1847d28cc183ec23c50bd5bca52a1b21'))

    Test('i7-min-6G60.inf', memsettings={'ZCODE_FILE_END_PADDING':0},
         res=_ok(md5='0214595edb8233dfec4c051d758a4e18', reg='i7-min-6G60.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8,
         res=_ok(md5='2ed4f9a623ad7e3c5407c7f8fca5d59a', reg='Advent-z.reg'))

    Test('library_of_horror-16.inf', includedir='punylib-16', zversion=3, memsettings={'ZCODE_FILE_END_PADDING':0},
         res=_ok(md5='84602222ee9eb1f5c986817b6b8e0be9'))

    Test('library_of_horror-36.inf', includedir='punylib-36', memsettings={'ZCODE_FILE_END_PADDING':0}, zversion=3,
         res=_ok(md5='b5985a139e8aa6622c2a0ac515da3a41', reg='library_of_horror.reg'))


class Run_ZCode_Compact_Globals(TestGroup, key='ZCODE_COMPACT_GLOBALS'):
    Test('show_globals.inf',
         res=_ok(reg='show_globals-z5.reg'))

    Test('show_globals.inf', zversion=3,
         res=_ok(reg='show_globals-z3.reg'))

    Test('show_globals.inf', memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(reg='show_globals-z5-compact.reg'))

    Test('show_globals.inf', zversion=3, memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(reg='show_globals-z3-compact.reg'))

    Test('show_globals.inf', define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals-z5-short.reg'))

    Test('show_globals.inf', zversion=3, define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals-z3-short.reg'))

    Test('show_globals.inf', memsettings={'ZCODE_COMPACT_GLOBALS':1}, define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals-z5-compact-short.reg'))

    Test('show_globals.inf', zversion=3, memsettings={'ZCODE_COMPACT_GLOBALS':1}, define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals-z3-compact-short.reg'))

    
    Test('show_globals_1v.inf',
         res=_ok(reg='show_globals_1v-z5.reg'))

    Test('show_globals_1v.inf', zversion=3,
         res=_ok(reg='show_globals_1v-z3.reg'))

    Test('show_globals_1v.inf', memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(reg='show_globals_1v-z5-compact.reg'))

    Test('show_globals_1v.inf', zversion=3, memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(reg='show_globals_1v-z3-compact.reg'))

    Test('show_globals_1v.inf', define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals_1v-z5-short.reg'))

    Test('show_globals_1v.inf', zversion=3, define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals_1v-z3-short.reg'))

    Test('show_globals_1v.inf', memsettings={'ZCODE_COMPACT_GLOBALS':1}, define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals_1v-z5-compact-short.reg'))

    Test('show_globals_1v.inf', zversion=3, memsettings={'ZCODE_COMPACT_GLOBALS':1}, define={ 'SHORTARRAY':0 },
         res=_ok(reg='show_globals_1v-z3-compact-short.reg'))

    
    Test('compact_array_bug.inf',
         res=_ok(md5='078bbc65e40ce215711c74ca14148716', reg='allpass.reg'))

    Test('compact_array_bug.inf', memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(md5='346959ef2cc13a2f9ae0fac5aa829d0a', reg='allpass.reg'))

    
    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(md5='084c43133cfe235065af7193847959e5', warnings=0, reg='Advent-z.reg'))

    Test('library_of_horror-36.inf', includedir='punylib-36', zversion=3, memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(md5='14a41b12eb4278101a2f7f33ac6b5bf2', reg='library_of_horror.reg'))


test_catalog = [ (grp.key, grp) for grp in TestGroup.groups ]
test_map = dict(test_catalog)

if (opts.listtests):
    print('Tests in this suite:')
    for (key, grp) in test_catalog:
        print(' %-30s (%d tests)' % (key, len(grp.tests),))
    sys.exit(-1)

if opts.alignment not in (1, 4, 16):
    print('Alignment must be 1, 4, or 16.')
    sys.exit(-1)

if not os.path.exists(opts.binary):
    print('Inform binary not found:', opts.binary)
    sys.exit(-1)

if not os.path.exists('build'):
    os.mkdir('build')

# Figure out which arguments are test groups and which are filename
# filters. Good thing filenames always contain dots and test groups
# never do.
    
filterargs = []
groupargs = []
for arg in args:
    if '.' in arg or '*' in arg:
        filterargs.append(arg)
    else:
        groupargs.append(arg)
    
if not groupargs:
    groupargs = [ key for (key, grp) in test_catalog ]

for key in groupargs:
    key = key.upper()
    grp = test_map.get(key)
    if (not grp):
        set_testname(key)
        note_error(None, 'No such test group!')
        continue
    grp.runtests(filterargs)
    
print()

if (not errorlist):
    print('All %d tests passed.' % (len(testlist),))
else:
    print('%d test failures!' % (len(errorlist),))
    for (test, label, msg) in errorlist:
        print('  %s (%s): %s' % (test, label, msg))

