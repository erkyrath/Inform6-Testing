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
            debugfile=False, transcriptfile=False,
            bigmem=False,
            makemodule=False, usemodules=False):
    """Perform one Inform compile, and return a Result object.

    By default, this compiles to the Inform default target (z5). You
    can pass zversion=N or glulx=True to build a different target.
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
    - transcriptfile generates gametext.txt (-r)
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
    if transcriptfile:
        showargs.append('-r')
        showargs.append('+transcript_name=build/gametext.txt')
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
    
    def canonical_transcriptfile_checksum(self, filename):
        """ Load a gametext file and construct an MD5 checksum, allowing for
        differences in compiler version.
        """
        infl = open(filename, 'rb')
        dat = infl.read()
        infl.close()

        pat = re.compile(b'\\[From Inform 6[.][^]]+\\]')
        dat = pat.sub(b'[From Inform 6...]', dat)
        pat = re.compile(b'\\[End of transcript: release [0-9]+, serial [0-9]+\\]')
        dat = pat.sub(b'[End of transcript: release ..., serial ...]', dat)
        
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

    def is_ok(self, md5=None, md5match=None, reg=None, abbreviations=None, debugfile=None, transcriptfile=None, warnings=None):
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
        file matches (the md5 checksum). Similarly with transcriptfile
        and gametext.txt.
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
            if transcriptfile is not None:
                val = self.canonical_transcriptfile_checksum('build/gametext.txt')
                if val != transcriptfile:
                    note_error(self, 'gametext.txt mismatch: %s is not %s' % (val, transcriptfile,))
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
         res=_ok(md5='c44b9a95823e2ff499a81fc0ef2e6ea2', warnings=0))
    
    Test('i7-min-6G60.inf',
         res=_ok(md5='fa69553d9e2a5917928b6d1b30b38c0f', md5match='i7-min-6G60:z', reg='i7-min-6G60.reg'))

    Test('i7-min-6G60.inf', zversion=8,
         res=_ok(md5='24cf678fc077291ab045280f44fe95f7', reg='i7-min-6G60.reg'))

    Test('i7-min-6G60.inf', glulx=True,
         res=_ok(md5='2c69bf065bef9d5b6ddd12b83b846745', md5match='i7-min-6G60:g', reg='i7-min-6G60.reg'))

    Test('i7-min-6M62-z.inf', zversion=8,
         res=_ok(md5='3e2d070d09d98fb054066f9dff2f834f', reg='i7-min-6M62.reg'))

    Test('i7-min-6M62-g.inf', glulx=True,
         res=_ok(md5='b39c17f23d3ae80403ce8e841ae2ec3c', reg='i7-min-6M62.reg'))

    Test('i7-min-10-1-2.inf', glulx=True,
         res=_ok(md5='7473b5d5b51682a778551f5841adf16e', reg='i7-min-10.reg'))

    Test('Advent.inf', includedir='i6lib-611',
         res=_ok(md5='39e332cb533985f5fd22a76cb1b93b45', md5match='Advent:z', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8,
         res=_ok(md5='7ea18d6a2f7da766cce549cfcaa3b44a', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='3bd969ddadb139f028e9cc6d0d5534cc', md5match='Advent:g', warnings=0, reg='Advent-g.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8, strict=False,
         res=_ok(md5='fc105a4024a59e0ff15e302d57155776', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True, strict=False,
         res=_ok(md5='27837de129ec0b6ac57cb88b22c85023', warnings=0, reg='Advent-g.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8, debug=True,
         res=_ok(md5='b66d0af02b0716e8d0a68bf343a67115', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True, debug=True,
         res=_ok(md5='e472575804f7fb5325f3f0527fb9f8d2', warnings=0, reg='Advent-g.reg'))

    Test('Advent.inf', includedir='i6lib-611', infix=True,
         res=_ok(md5='03ef1fdadf0a389220c7ce0204741f88', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-6.12.6',
         res=_ok(md5='d9729da5b8d8b8b419298ca985d42347', warnings=0))

    Test('Advent.inf', includedir='i6lib-6.12.6', glulx=True,
         res=_ok(md5='c4bd486a6a1ff53ce9d8965f98921684', warnings=1))

    Test('box_quote_test.inf', includedir='i6lib-611',
         res=_ok(md5='978db958d32c55954463576b310afaca', warnings=0))

    Test('cloak-metro84-v3test.inf', zversion=3, economy=False,
         res=_ok(md5='af7d07712bb76d70afdac7b7424ec062', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=4, economy=False,
         res=_ok(md5='6493b2c2704f15ec99ac753e52069d3d', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=5, economy=False,
         res=_ok(md5='bdf521b5b77496be7ffb6577be5dd49e', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=3, economy=True,
         res=_ok(md5='53a74ec4bb3d1e7b033a755a3a924a8d', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=4, economy=True,
         res=_ok(md5='3ceaefd25c9b1719a50f39da8bced00d', warnings=2, reg='cloak-metro84.reg'))

    Test('cloak-metro84-v3test.inf', zversion=5, economy=True,
         res=_ok(md5='77d52387e849ef4b8d5fb393d663cec6', warnings=2, reg='cloak-metro84.reg'))

    Test('library_of_horror-16.inf', includedir='punylib-16', zversion=3,
         res=_ok(md5='39ef33340670084b98af8ad35932597e'))

    Test('library_of_horror-16.inf', includedir='punylib-16', zversion=3, memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='ea7735372b96d7df9d1c687625db603b'))

    # OMIT_UNUSED_ROUTINES is set in the source
    Test('library_of_horror-36.inf', includedir='punylib-36', zversion=3,
         res=_ok(md5='d5d0e2c1b5b816301f6a2fd0b97295c7', reg='library_of_horror.reg'))

    # OMIT_UNUSED_ROUTINES is set in the source; GV3 is set in the library.
    Test('library_of_horror-60.inf', includedir='punylib-60', zversion=3,
         res=_ok(md5='b2fdf970847c4467119c3f13543b3ee1', reg='library_of_horror.reg'))
    
    Test('library_of_horror-60.inf', includedir='punylib-60', zversion=3, memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='4ed5aeefb91710dd362089306c84296e', md5match='library_of_horror-60:meta=1', reg='library_of_horror.reg'))


class Run_Dict(TestGroup, key='DICT'):
    Test('dict-size-v3test.inf', zversion=3,
         res=_ok(md5='68b57b14d5ca770be53134d8f4739727', reg='allpass.reg'))

    Test('dict-size-v3test.inf', zversion=5,
         res=_ok(md5='1e118d8af5a9dfa2ec4da89aaaa77dd3', reg='allpass.reg'))

    Test('dict-cutoff-v3test.inf', strict=False, zversion=3,
         res=_ok(md5='9041b8a2404806b50a21debd32f35261', reg='allpass.reg'))

    Test('dict-cutoff-v3test.inf', strict=False, zversion=4,
         res=_ok(md5='7c5ff735099ef692dd3d14782c0a9ad9', reg='allpass.reg'))

    Test('dict-cutoff-v3test.inf', strict=False, zversion=5,
         res=_ok(md5='84f3fd0303b39f454fa29145c14d86ea', reg='allpass.reg'))

    Test('dict-cutoff-alttest.inf', strict=False, zversion=5,
         res=_ok(md5='5c04f7ceddb7443146853213828df6db', reg='allpass.reg'))

    Test('dict-cutoff-alttest.inf', strict=False, zversion=8,
         res=_ok(md5='144afa525d7b386aa9487b7cd30c918c', reg='allpass.reg'))

    Test('max_dict_entries.inf',
         res=_ok())

    Test('max_dict_entries.inf', glulx=True,
         res=_ok())

    Test('dict-entry-size-test.inf', zversion=3, strict=False,
         res=_ok(md5='281c7d7e39ab27064c89b53d77bc8345'))

    # The checksum here is different because the "Version 3" directive doesn't work perfectly
    Test('dict-entry-size-test.inf', zversion=3, strict=False, define={'EARLYDEF':None}, versiondirective=True,
         res=_ok(md5='2387e57d58f2d5d0c195957d92c0b8e1'))

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
         res=_ok(md5='d9d693d963124540af24ce33ad83c781'))

    Test('dict-entry-size-test.inf', zversion=5,
         res=_ok(md5='131442d49ae7891f212b38bcab81d52a'))

    Test('dict-entry-size-test.inf', zversion=5, memsettings={'ZCODE_LESS_DICT_DATA':1},
         res=_ok(md5='8eed22965d44d92bb5061ea9fceac172'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_LESS_DICT_DATA':1},
         res=_ok(md5='4b96bed3903697a235fa54f556aca55c', warnings=0, reg='Advent-z.reg'))

    Test('dict-sysconst-test.inf',
         res=_ok(md5='47b62a91364d91a17305d716201cd3fc', reg='allpass.reg'))

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
         res=_ok(md5='887962327570f57818e8bf22b3d80b2a', reg='i7-min-6M62.reg'))

    Test('i7-min-6M62-g.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True,
         res=_ok(md5='ed273f9b19ea00b2873a7c9144f415bb', reg='i7-min-6M62.reg'))

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
         res=_ok(md5='3aaf39e4a4a63ecaf248a987f23828c2', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611w,i6lib-611', glulx=True,
         res=_ok(md5='de05c4c19f5196fc887dc6e377792603', warnings=0, reg='Advent-g.reg'))

    Test('dictlargeentrytest.inf', glulx=True,
         res=_ok(md5='703d17e3ce8bf8b1a47d9764189ccad6', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='0f04d6232789603d32a81d27a72f3cc1', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':30},
         res=_ok(md5='204703590f0839a64683843d8663167c', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':30, 'DICT_CHAR_SIZE':4},
         res=_ok(md5='99696bdbd8c9410742eb1e15dec717ba', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':35},
         res=_ok(md5='3f564b59e85af0f4a6197b4ecb924da4', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':35, 'DICT_CHAR_SIZE':4},
         res=_ok(md5='ef1fa6c9043e12115a5c0314c62d196a', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':144},
         res=_ok(md5='475b87c748e58cf17c081da709097646', reg='allpass.reg'))
    
    Test('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':144, 'DICT_CHAR_SIZE':4},
         res=_ok(md5='74f929db0e483dde87109a1855002e07', reg='allpass.reg'))
    

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
         res=_ok(md5='fa69553d9e2a5917928b6d1b30b38c0f', md5match='i7-min-6G60:z', reg='i7-min-6G60.reg'))

    # Advent with GRAMMAR_META_FLAG should run correctly
    Test('Advent.inf', includedir='i6lib-611', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='be866e8bcf38c83c2be6c4f612ec1f7c', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', glulx=True, memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='56b547a1d720a4e86c68fcd4d5071bcf', warnings=0, reg='Advent-g.reg'))

    # Requires GRAMMAR_META_FLAG
    Test('grammar-metaflag-test.inf',
         res=_error())

    Test('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='65f30db8f7e430c75a25b3c8c908b525', reg='allpass.reg'))

    Test('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1, 'GRAMMAR_VERSION':2},
         res=_ok(md5='419f50fe0b1d3f814461c2ab9bcc1d27', reg='allpass.reg'))

    Test('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, glulx=True,
         res=_ok(md5='e73fe079f68a83f4af3bbdaa62e4cc37', reg='allpass.reg'))


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
         res=_ok(md5='2ff6e2ccbdf7f034e462383b8626c3d6', reg='allpass.reg'))

    Test('action-compare-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='b4fd62b72e931418a7ef184b5d898f55', reg='allpass.reg'))

    Test('action-compare-test.inf', glulx=True,
         res=_ok(md5='f55e0b5fac34ba1e785ec0385c87cc65', reg='allpass.reg'))

    Test('action-compare-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, glulx=True,
         res=_ok(md5='e86359b60b25cefbee4a827d5bdbb910', reg='allpass.reg'))

    
    Test('grammar-dump-test.inf',
         res=_ok(md5='1e39226debe7f37cd159850159779b7f', reg='grammardump-gv1.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2},
         res=_ok(md5='301adf74d1d0d7a193cadfd102743ff3', reg='grammardump-gv2.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':3},
         res=_ok(md5='831e3892f3150ab989be741bc2b963eb', reg='grammardump-gv3.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2}, glulx=True,
         res=_ok(md5='73700316b6f9efc87ea2c2b4546dc5c7', reg='grammardump-gv2.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='df7871020f5eecd4e1b9140d6b670a4c', reg='grammardump-gv1-meta.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2, 'GRAMMAR_META_FLAG':1},
         res=_ok(md5='ca1de0cf35ec74d100f7d46c0e5c0cd9', reg='grammardump-gv2-meta.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':3, 'GRAMMAR_META_FLAG':1},
         res=_ok(md5='6eae8481d29eb572d0b60cf5470060bc', reg='grammardump-gv3-meta.reg'))
    
    Test('grammar-dump-test.inf', memsettings={'GRAMMAR_VERSION':2, 'GRAMMAR_META_FLAG':1}, glulx=True,
         res=_ok(md5='6c577e1d3f4d9bffc62cf9a2cc6da915', reg='grammardump-gv2-meta.reg'))
    
    
    # Compile with the GV3 parser.
    Test('Advent.inf', includedir='i6lib-611gv3,i6lib-611',
         res=_ok(md5='fea479b76a3aa48b76f3628f05461aa6', warnings=0, reg='Advent-z.reg'))

    # Compile with GRAMMAR_META_FLAG
    Test('library_of_horror-60.inf', includedir='punylib-60meta,punylib-60', zversion=3,
         res=_ok(md5='4ed5aeefb91710dd362089306c84296e', md5match='library_of_horror-60:meta=1'))

    # Compile with the modified parser; meta verbs should be meta.
    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', memsettings={'GRAMMAR_META_FLAG':1}, debug=True,
         res=_ok(md5='9fb9f503734f7b5e56dc51b214ba7fe4', md5match='withdaemon:z:meta=1', warnings=0))
    
    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', debug=True, define={'SET_META_CONST':None},
         res=_ok(md5='9fb9f503734f7b5e56dc51b214ba7fe4', md5match='withdaemon:z:meta=1', warnings=0))
    
    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', memsettings={'GRAMMAR_META_FLAG':1}, debug=True, glulx=True,
         res=_ok(md5='d5a9fec733f869815f7bca9dec99501d', md5match='withdaemon:g:meta=1', warnings=0))

    Test('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', define={'SET_META_CONST':None}, debug=True, glulx=True,
         res=_ok(md5='d5a9fec733f869815f7bca9dec99501d', md5match='withdaemon:g:meta=1', warnings=0))

    
    # All of the following should compile the same.
    Test('verbclash.inf', includedir='i6lib-611', define={'EXTENDLAST':None},
         res=_ok(md5='fb7fb5f6e80917a8ce87515d0a9038c1', md5match='verbclash', warnings=0))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'EXACTSAME':None},
         res=_ok(md5='fb7fb5f6e80917a8ce87515d0a9038c1', md5match='verbclash', warnings=1))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'CASESAME':None},
         res=_ok(md5='fb7fb5f6e80917a8ce87515d0a9038c1', md5match='verbclash', warnings=1))
    
    Test('verbclash.inf', includedir='i6lib-611', define={'TRUNCSAME':None},
         res=_ok(md5='fb7fb5f6e80917a8ce87515d0a9038c1', md5match='verbclash', warnings=1))
    
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
    Test('escape-doubleat.inf',
         res=_ok(md5='be0db6b8010a4373e37f9df192ef66c2', reg='escape-both.reg'))
    
    Test('escape-doubleat.inf', glulx=True,
         res=_ok(md5='7a74f126a7952b0dfab1f0b54acd9fe1', reg='escape-both.reg'))
    
    Test('escape-doubleat.inf', define={'BAD_NO_DIGITS':None},
         res=_error())
    
    Test('escape-doubleat.inf', define={'BAD_NO_DIGITS':None}, glulx=True,
         res=_error())
    
    Test('escape-doubleat.inf', define={'BAD_DICT_ABBREV':None},
         res=_error())
    
    Test('escape-doubleat.inf', define={'BAD_DICT_ABBREV':None}, glulx=True,
         res=_error())
    
    Test('escape-brace.inf',
         res=_ok(md5='be0db6b8010a4373e37f9df192ef66c2', reg='escape-both.reg'))
    
    Test('escape-brace.inf', glulx=True,
         res=_ok(md5='7a74f126a7952b0dfab1f0b54acd9fe1', reg='escape-both.reg'))
    
    Test('escape-brace.inf', define={'BAD_NO_DIGITS':None},
         res=_error())
    
    Test('escape-brace.inf', define={'BAD_NO_DIGITS':None}, glulx=True,
         res=_error())

    Test('escape-brace.inf', define={'BAD_SEVEN_DIGITS':None},
         res=_error())
    
    Test('escape-brace.inf', define={'BAD_SEVEN_DIGITS':None}, glulx=True,
         res=_error())

    
    Test('unisourcetest.inf', glulx=True,
         res=_ok(md5='688851a8786e1ef64c0214899560bd0f', reg='unisourcetest.reg'))
    
    Test('source-encoding-1.inf',
         res=_ok(md5='6fd5bec8f5ff765818ef44b0408ecd4a', reg='source-encoding-1.reg'))

    # No output check because the file has no Glk setup
    Test('source-encoding-1.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='fdf57843cda63f15ffc4eca3ed872d0b'))
    
    Test('source-encoding-7.inf',
         res=_ok(md5='08b5fd4d00bbf90e1f94240493e38bdd', reg='source-encoding-7.reg'))

    # No output check because the file has no Glk setup
    Test('source-encoding-7.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='a0eeaa8b90fbd2923482830e0cc1986e'))
    
    Test('source-encoding-u.inf',
         res=_ok(md5='644bd6e55b30520a182dad4bc3b61a27', reg='source-encoding-u.reg'))

    # No output check because the file has no Glk setup
    Test('source-encoding-u.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4},
         res=_ok(md5='d8ac6c6191086e52fe9206270e86b068'))

    Test('zalphabet-direct.inf',
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))
    
    Test('zalphabet-header.inf',
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-header-esc.inf',
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-:()'},
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789@{2E},!?_@{00023}@@39/\\-:()'},
         res=_ok(md5='996c6a5dacd3d87a345918c1de50c12a', md5match='zalphabet'))

    Test('zalphabet-classbad.inf',
         res=_ok(md5='819856136bcc485ab3d39664574bb9bc'))
    
    Test('zalphabet-classname.inf',
         res=_ok(md5='973c0a3bcd4006674ad5213c5555e3a3', md5match='zalphabet-class', reg='zalphabet-classname.reg'))
    
    Test('zalphabet-classdir.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqstruvwxyz BCDEFGHIJKLMNOPQRSTUVWXYZA 0123456789.,!?_@{23}\'/\\-:()'},
         res=_ok(md5='973c0a3bcd4006674ad5213c5555e3a3', md5match='zalphabet-class'))
    
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

    # Seven chars in braces
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-@{000003A}()'},
         res=_error())

    # Non-hex character in braces
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-@{123x}()'},
         res=_error())

    # Unterminated braces
    Test('zalphabet-base.inf', memsettings={'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#\'/\\-()@{123'},
         res=_error())

    Test('zalphabet-direct-bad.inf',
         res=_ok())
    
    Test('zalphabet-direct-bad.inf', define={'STRING_CONSTANT':None},
         res=_error(errors=1))
    
    Test('zalphabet-direct-bad.inf', define={'DEF_OBJECT':None},
         res=_error(errors=1))
    
    Test('ztable-direct.inf',
         res=_ok(md5='c028ee0aaabeb9a1c9c5169b81289428', md5match='ztable'))

    # Unicode characters not placed in the table
    Test('ztable-base.inf',
         res=_error())

    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'+ @@945 @{3B2} @@947 @{2655} @@9812'},
         res=_ok(md5='c028ee0aaabeb9a1c9c5169b81289428', md5match='ztable', reg='ztable-base.reg'))

    Test('ztable-header.inf',
         res=_ok(md5='c028ee0aaabeb9a1c9c5169b81289428', md5match='ztable'))

    # Non-ascii
    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'+ \u03b1 @{3B2} @@947 @{2655} @@9812'},
         res=_error())

    # Ascii
    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'+ A @{03b1} @{3B2} @@947 @{2655} @@9812'},
         res=_error())

    # Double plus
    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'++@{03b1} @{3B2} @@947 @{2655} @@9812'},
         res=_error())

    # Non-hex character in braces
    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'+ @@945 @{3q2} @@947 @{2655} @@9812'},
         res=_error())

    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'+ @@945 @{3B2} @@947 @{2655} @@9812', 'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_@{3B1}@@9813/\\-:()'},
         res=_ok(md5='408129f018633049450fd117d4627bb5', reg='ztable-base.reg'))

    # Non-plus form of ZCHAR_TABLE
    # (This does not print the "as single chars" line correctly, because ZSCII $E3/$E4 wind up undefined.)
    Test('ztable-base.inf', memsettings={'ZCHAR_TABLE':'@@945 @{3B2} @@947 @{2655} @@9812 @{E4} @{E9} @@248', 'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_@{3B1}@@9813/\\-:()'},
         res=_ok(md5='d955aa2413a2d410d0e88d4eab509cd8'))

    # Too many chars to fit in the extension table
    Test('ztable-toomany.inf',
         res=_error())

    Test('ztable-prec-head.inf',
         res=_ok(md5='1f1bf743783733ee962d784b4162dcd3', md5match='ztable-prec', reg='ztable-base.reg'))

    Test('ztable-prec.inf',
         res=_error())

    Test('ztable-prec.inf', memsettings={'ZCHAR_TABLE':'+ @@945 @{3B2} @{3b3} @{2655} @@9812', 'ZALPHABET':'abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789.,!?_#@{3B2}/\\-@{2655}()'},
         res=_ok(md5='1f1bf743783733ee962d784b4162dcd3', md5match='ztable-prec'))

    # Error cases

    Test('zalphabet-direct.inf', zversion=3,
         res=_error())

    Test('zalphabet-direct.inf', zversion=4,
         res=_error())

    # This compiles, but the $ZALPHABET is entirely ignored.
    Test('zalphabet-classname.inf', zversion=3,
         res=_ok(md5='a55d651703fdc0dbf917f8abff7021f1', reg='zalphabet-classname.reg'))

    Test('zalphabet-classname.inf', zversion=4,
         res=_ok(md5='4d3adde77631ffe71546e28b45957457', reg='zalphabet-classname.reg'))


class Run_Header(TestGroup, key='HEADER'):

    # The test file prints out the runtime values of the flags.
    # We're not going to check that, because it would wind up being
    # a test of Bocfel behavior rather than Inform behavior.
    
    Test('zflags_test.inf',
         res=_ok(md5='664639559b427ffba6d38950b86de5a2', md5match='zflags_test:z5'))

    Test('zflags_test.inf', zversion=3,
         res=_ok(md5='008cdb7135f358e1bdac3b965038874b', md5match='zflags_test:z3'))

    Test('zflags_test.inf', zversion=6,
         res=_ok(md5='477b541ed00a52f7de5f8975ae022673', md5match='zflags_test:z6'))

    Test('zflags_test.inf', memsettings={'ZCODE_HEADER_FLAGS_1':129},
         res=_ok(md5='e0f305b40f01010c74d6b7e225e84771'))

    Test('zflags_test.inf', memsettings={'ZCODE_HEADER_FLAGS_2':513},
         res=_ok(md5='76ff5862a274a8c009a9471a6e6da6ce'))

    Test('zflags_test.inf', memsettings={'ZCODE_HEADER_FLAGS_3':1027},
         res=_ok(md5='71da9b3f90d20f1ad9a03128b8131df1'))

    # flags2 bit 7
    Test('zflags_test.inf', define={'SOUND_EFFECT':None},
         res=_ok(md5='1df24f479257b73232b10dcbdd9c30e2'))

    # flags2 bit 7 is cleared
    Test('zflags_test.inf', define={'SOUND_EFFECT':None}, memsettings={'ZCODE_HEADER_FLAGS_2_CLR':128},
         res=_ok(md5='9293b267217b6bc52401b9f39b4408ed'))

    # flags2 bit 6
    Test('zflags_test.inf', define={'SET_COLOUR':None},
         res=_ok(md5='028aef3a813e37832795b6d86644a419'))

    # flags2 bit 4
    Test('zflags_test.inf', define={'SAVE_UNDO':None},
         res=_ok(md5='1e8ce3dd53226cc096db493ceea29b2c'))

    # flags2 bit 4 is cleared, and the func_save_undo() routine is dropped,
    # so this is exactly the same as the original
    Test('zflags_test.inf', define={'SAVE_UNDO':None}, memsettings={'ZCODE_HEADER_FLAGS_2_CLR':16, 'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='664639559b427ffba6d38950b86de5a2', md5match='zflags_test:z5'))

    # flags2 bit 3
    Test('zflags_test.inf', zversion=6, define={'DRAW_PICTURE':None},
         res=_ok(md5='a4e563f37e6bc4704eb5afed4c7d8146'))

    # flags2 bit 5
    Test('zflags_test.inf', zversion=6, define={'MOUSE_WINDOW':None},
         res=_ok(md5='07cbc1552eb9a0cd0a322415332dd528'))

    # flags2 bit 8
    Test('zflags_test.inf', zversion=6, define={'MAKE_MENU':None},
         res=_ok(md5='8d7efefe846f9fd0ca657bfa1c1f613f'))

    # clear bit and drop routine
    Test('zflags_test.inf', zversion=6, define={'MAKE_MENU':None}, memsettings={'ZCODE_HEADER_FLAGS_2_CLR':256, 'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='477b541ed00a52f7de5f8975ae022673', md5match='zflags_test:z6'))

    # flags1 bit 1
    Test('zflags_test.inf', zversion=3, define={'STATUS_TIME':None},
         res=_ok(md5='df5a8822d44b71c69536b8d00767f718', md5match='zflags_test:z3:f1=1'))

    # same
    Test('zflags_test.inf', zversion=3, memsettings={'ZCODE_HEADER_FLAGS_1':2},
         res=_ok(md5='df5a8822d44b71c69536b8d00767f718', md5match='zflags_test:z3:f1=1'))

    # clear bit
    Test('zflags_test.inf', zversion=3, define={'STATUS_TIME':None}, memsettings={'ZCODE_HEADER_FLAGS_1_CLR':2},
         res=_ok(md5='008cdb7135f358e1bdac3b965038874b', md5match='zflags_test:z3'))

    # flags2 bit 7 (with the current spec)
    Test('zflags_test.inf', zversion=3, define={'SOUND_EFFECT':None},
         res=_ok(md5='ee4e92eba8ae0d731654a3c295a20efe'))


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
         res=_ok(md5='b88c54b923b267d2b085196d2cec21b1', reg='staticarraytest-z.reg'))

    Test('staticarraytest.inf', glulx=True,
         res=_ok(md5='a9cbf3f12d3197205d3ca673ce177b53', reg='staticarraytest-g.reg'))

    Test('undefdirectivetest.inf',
         res=_ok(md5='3349a4ec0b3aa0d76350b70149c4a61d'))

    Test('undefdirectivetest.inf', glulx=True,
         res=_ok(md5='e6088bb858687385c3663779269f6fc9'))

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
         res=_ok(md5='367c1c25933b965c5ccd54fbd778918d'))

    Test('replacerenametest.inf', includedir='src', glulx=True,
         res=_ok(md5='917b1822fe840ffd9329664759dd4036'))

    Test('replacerecursetest.inf',
         res=_ok(md5='4e80bcb944e8d191ee0a3bd84ff94e93'))

    Test('replacerecursetest.inf', glulx=True,
         res=_ok(md5='eb8f41cd254efded24a1e8ca7e8734a8'))

    Test('dictflagtest.inf',
         res=_ok(md5='078a2caa60f2080f311ca0dcd4f24e0a'))

    Test('dictflagtest.inf', glulx=True,
         res=_ok(md5='d16ba8161e16d7f0c14a48dcbbd8b744'))

    Test('actionextension.inf',
         res=_ok(md5='2c73d58157fe15ca2021cb57fa54cf06'))

    Test('actionextension.inf', glulx=True,
         res=_ok(md5='f60725a37182d7cf38b2022621b2cac9'))

    Test('internaldirecttest.inf',
         res=_ok(md5='cdca1fc725779e9e344dc9b31a86c43f', reg='internaldirecttest.reg'))

    Test('internaldirecttest.inf', glulx=True,
         res=_ok(md5='322fc7283ec6ab3cb5b14c94cd3346a2', reg='internaldirecttest.reg'))

    Test('ifelsedirecttest.inf',
         res=_ok(md5='25ee91b7c1a03607802f96d0032529f4'))

    Test('ifelsedirecttest.inf', glulx=True,
         res=_ok(md5='4e221f2289f6d6cfc9c686d1a241f428'))

    Test('ifdef_vn_test.inf',
         res=_ok(md5='a8cbb33e62f907e0473842bb5c085d04'))

    Test('ifdef_vn_test.inf', glulx=True,
         res=_ok(md5='46c30eb35d2e0b19cdd53c39e5aa5b81'))

    Test('classordertest.inf',
         res=_ok(md5='6a5fa00474914544c9c8ec0d9db43ec6', reg='allpass.reg'))

    Test('classordertest.inf', glulx=True,
         res=_ok(md5='5119926466c17ae9b174fcdb33ccae87', reg='allpass.reg'))

    Test('classcopytest.inf',
         res=_ok(md5='ed4a2b9e0ca47bdf82f6976b8e28f0bd', reg='allpass.reg'))

    Test('classcopytest.inf', glulx=True,
         res=_ok(md5='f130fc73d9ec0f8c923f1f323bd2bbd8', reg='allpass.reg'))

    Test('forwardproptest.inf',
         res=_ok(md5='be12d01a003341561bf110ca6244434b', reg='allpass.reg'))

    Test('forwardproptest.inf', strict=False,
         res=_ok(md5='1d50b5b15171b26bea591ffa7a6cfd2e', reg='allpass.reg'))

    Test('forwardproptest.inf', glulx=True,
         res=_ok(md5='96cb5e78d2d4761b99691aab7e628c4f', reg='allpass.reg'))

    Test('forwardproptest.inf', glulx=True, strict=False,
         res=_ok(md5='678d9d2c339c11c434a0e2816d1056be', reg='allpass.reg'))

    Test('indivproptest.inf',
         res=_ok(md5='5adbb27f74047d53675794812a14d83a', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None},
         res=_ok(md5='5adbb27f74047d53675794812a14d83a', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV2':None},
         res=_ok(md5='091b2a4df396da37c19a3daf2cb7dd00', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None,'DEF_INDIV2':None},
         res=_ok(md5='c319ce9e62033647a4bcf8979854cbbc', reg='allpass.reg'))

    Test('indivproptest.inf', glulx=True,
         res=_ok(md5='3f30e40f886c931dd980f10c4c5573c6', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None}, glulx=True,
         res=_ok(md5='3f30e40f886c931dd980f10c4c5573c6', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV2':None}, glulx=True,
         res=_ok(md5='09a0b67b4eaaf19cf5b0673345ccc421', reg='allpass.reg'))

    Test('indivproptest.inf', define={'DEF_INDIV1':None,'DEF_INDIV2':None}, glulx=True,
         res=_ok(md5='fbd3454f8f2d05c5bf508d9f10c5bd0a', reg='allpass.reg'))

    Test('indivproptest_2.inf',
         res=_ok(md5='11d376a43d85ef7218e7fd9cff76f210', warnings=0, reg='allpass.reg'))

    Test('indivproptest_2.inf', define={'LONG_PROP_WARN':None},
         res=_ok(md5='11d376a43d85ef7218e7fd9cff76f210', warnings=1, reg='allpass.reg'))

    Test('indivproptest_2.inf', glulx=True,
         res=_ok(md5='7b8c0a8ad2ce45c891959d17ea8cf7db', warnings=0, reg='allpass.reg'))

    Test('indivproptest_2.inf', define={'LONG_PROP_WARN':None}, glulx=True,
         res=_ok(md5='7b8c0a8ad2ce45c891959d17ea8cf7db', warnings=1, reg='allpass.reg'))

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
         res=_ok(md5='524277179fc34ddf6a61a95dc34613e0', reg='base_class_prop.reg'))
    
    Test('base_class_prop.inf', zversion=5, includedir='punylib-36',
         res=_ok(md5='d1d27db99cc068eb37345cb8860c06e9', reg='base_class_prop.reg'))
    
    Test('base_class_prop_2.inf', zversion=3, includedir='punylib-36',
         res=_ok(md5='8d57de74d7170b286fc4e20bf593369c', reg='base_class_prop_2.reg'))
    
    Test('base_class_prop_2.inf', zversion=5, includedir='punylib-36',
         res=_ok(md5='31d88f07501dbfacf154817ae021a7bd', reg='base_class_prop_2.reg'))
    
    Test('obj_prop_test.inf',
         res=_ok(md5='f7f2e5aeda6d8a0d00b96f1364b4ad17', reg='obj_prop_test-z.reg'))
    
    Test('obj_prop_test.inf', strict=False,
         res=_ok(md5='cfee164f4ba85b901495a04ad9d51935', reg='obj_prop_test-z.reg'))
    
    Test('obj_prop_test.inf', zversion=3,
         res=_ok(md5='5743912e9ef7a8df58f044c1de4a9f6a', reg='obj_prop_test-z.reg'))
    
    Test('obj_prop_test.inf', glulx=True,
         res=_ok(md5='812bc71617f59e895dc595852fbeea40', reg='obj_prop_test-g.reg'))
    
    Test('obj_prop_test.inf', glulx=True, strict=False,
         res=_ok(md5='a432ce07bba157d0903276b87d2904cf', reg='obj_prop_test-g.reg'))
    

class Run_Veneer(TestGroup, key='ASM'):
    Test('bad-read-opcode.inf', zversion=3,
         res=_error(errors=1))

    Test('bad-read-opcode.inf', zversion=4,
         res=_error(errors=1))

    Test('bad-read-opcode.inf', zversion=5,
         res=_error(errors=1))

    Test('bad-read-opcode.inf', zversion=6,
         res=_error(errors=1))

    Test('bad-read-opcode.inf', zversion=8,
         res=_error(errors=1))


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
         res=_ok(md5='75e6fc55014ff76d18f440df240803bc', md5match='jumpopcodetest:z'))

    Test('jumpopcodetest.inf', define={'OPFORM':None},
         res=_ok(md5='75e6fc55014ff76d18f440df240803bc', md5match='jumpopcodetest:z'))

    Test('jumpopcodetest.inf', glulx=True,
         res=_ok(md5='fffa488a3c3bd39b0cc3387121284e3e', md5match='jumpopcodetest:g'))

    Test('jumpopcodetest.inf', glulx=True, define={'OPFORM':None},
         res=_ok(md5='fffa488a3c3bd39b0cc3387121284e3e', md5match='jumpopcodetest:g'))

    Test('jumpbadtest.inf',
         res=_error())

    Test('jumpbadtest.inf', glulx=True,
         res=_error())

    Test('branchbadtest.inf',
         res=_error())

    Test('branchbadtest.inf', glulx=True,
         res=_error())


class Run_BraceBlocks(TestGroup, key='BRACEBLOCKS'):
    Test('braceblocks-orig.inf',
         res=_ok(md5match='braceblocks:z'))

    Test('braceblocks-new.inf',
         res=_ok(md5match='braceblocks:z'))

    Test('braceblocks-new2.inf',
         res=_ok(md5match='braceblocks:z'))

    Test('braceblocks-orig.inf', glulx=True,
         res=_ok(md5match='braceblocks:g'))

    Test('braceblocks-new.inf', glulx=True,
         res=_ok(md5match='braceblocks:g'))

    Test('braceblocks-new2.inf', glulx=True,
         res=_ok(md5match='braceblocks:g'))

    Test('braceblocks-bad.inf', define={'BADBREAK1':None},
         res=_error())

    Test('braceblocks-bad.inf', define={'BADBREAK2':None},
         res=_error())

    Test('braceblocks-bad.inf', define={'BADCONTINUE':None},
         res=_error())

    Test('braceblocks-bad.inf', define={'NOCLOSE1':None},
         res=_error())

    Test('braceblocks-bad.inf', define={'NOCLOSE2':None},
         res=_error())


class Run_Expressions(TestGroup, key='EXPRESSIONS'):
    Test('unaryop_err_test.inf',
         res=_ok(md5='1ccc883543a85d69a3ca3ee4003533dd', reg='allpass.reg'))

    Test('unaryop_err_test.inf', glulx=True,
         res=_ok(md5='67740b1a7ad2afb9db561d7942847ddb', reg='allpass.reg'))

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
         res=_ok(md5='5de81e36f830f6c64fa48b7516e0c434'))

    Test('randomfunc.inf', glulx=True,
         res=_ok(md5='a58c2b567ce7b86a79c34716d401aaee'))

    Test('sysfunc.inf',
         res=_ok(md5='ada3be1c2d1f80d1646c0fe211fca971', reg='allpass.reg'))

    Test('sysfunc.inf', glulx=True,
         res=_ok(md5='a3ed63ee0c3da7ae236e3c5ff36d5007', reg='allpass.reg'))

    Test('sysfunc.inf', strict=False,
         res=_ok(md5='4b82dd5e6f9aff78983b654343432268', reg='allpass.reg'))

    Test('sysfunc.inf', glulx=True, strict=False,
         res=_ok(md5='acdb6e7d03acd16350c775a2e89a978a', reg='allpass.reg'))

    # non-strict because we're testing low-level prop opcodes
    Test('prop_store_optim.inf', strict=False,
         res=_ok(md5='8d796a2371a430735ad03777363a096f', reg='allpass.reg'))
    
    Test('prop_store_optim.inf', strict=False, glulx=True,
         res=_ok(md5='790b2f27086bd4411e7c73ea82100ee9', reg='allpass.reg'))
    

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
         res=_ok(md5='6f478bac59c624208632186763ee6e77', reg='allpass.reg'))

    Test('branchprune.inf', glulx=True,
         res=_ok(md5='751662e8976d4c37508b5f2f63f645ef', reg='allpass.reg'))

    Test('branchprune.inf', define={ 'BAD_JUMPS':None },
         res=_error())

    Test('branchprune.inf', define={ 'BAD_JUMPS':None }, glulx=True,
         res=_error())

    Test('branchprune.inf', define={ 'BAD_JUMPS':None }, memsettings={'STRIP_UNREACHABLE_LABELS':0 },
         res=_ok(md5='7332e54fcb592b3e812d75604e601558', reg='allpass.reg'))

    Test('branchprune.inf', define={ 'BAD_JUMPS':None }, memsettings={'STRIP_UNREACHABLE_LABELS':0 }, glulx=True,
         res=_ok(md5='bf8386d2b83c07287f9a1e27887f751b', reg='allpass.reg'))

    Test('branchprune-fwd.inf',
         res=_ok(md5='133af97419799866915cdfd927303c89', warnings=1, reg='allpass.reg'))

    Test('branchprune-fwd.inf', glulx=True,
         res=_ok(md5='5f2442c3f9bd2040806ae3d766e17788', warnings=1, reg='allpass.reg'))

    Test('branchprune-nowarn.inf',
         res=_ok(md5='a961b02b9c344d957d2a4fd482da0464', md5match='branchprune-nowarn:z:strip', warnings=0))

    Test('branchprune-nowarn.inf', glulx=True,
         res=_ok(md5='170eae8487d1ce20b88de8beee1f9d5c', md5match='branchprune-nowarn:z', warnings=0))

    Test('branchprune-nowarn.inf', memsettings={'STRIP_UNREACHABLE_LABELS':0 },
         res=_ok(md5='a961b02b9c344d957d2a4fd482da0464', md5match='branchprune-nowarn:z:strip', warnings=0))

    Test('branchprune-nowarn.inf', memsettings={'STRIP_UNREACHABLE_LABELS':0 }, glulx=True,
         res=_ok(md5='170eae8487d1ce20b88de8beee1f9d5c', md5match='branchprune-nowarn:z', warnings=0))

    Test('logicprune.inf',
         res=_ok(md5='b8d14b8a3d126e706436f54cdd9f8f22', warnings=0, reg='allpass.reg'))

    Test('logicprune.inf', glulx=True,
         res=_ok(md5='9295447c00c8bcf523de931d54dc8469', warnings=0, reg='allpass.reg'))

    Test('branchreduce.inf',
         res=_ok(md5='a471918a326aae37faf39c6cc71ce6ab', warnings=0, reg='allpass.reg'))
    
    Test('branchreduce.inf', strict=False,
         res=_ok(md5='72cc1c5aaea852d3288fa53b79f527e8', warnings=0, reg='allpass.reg'))
    
    Test('branchreduce.inf', zversion=3,
         res=_ok(md5='0840887793dc2db0ba72af277f09359e', warnings=0, reg='allpass.reg'))
    

    Test('branchcorner.inf',
         res=_ok(md5='c1957a298716da0b8d7ad6d6bb43f293', warnings=0, reg='allpass.reg'))
    
    Test('branchcorner.inf', strict=False,
         res=_ok(md5='874ed3548917ad7c8b23ef4402b8bd04', warnings=0, reg='allpass.reg'))
    
    Test('branchcorner.inf', glulx=True,
         res=_ok(md5='ebcbcb8315190d5c0e30ba9187af2537', warnings=0, reg='allpass.reg'))
    
    
    Test('tasksacktest.inf', includedir='i6lib-611',
         res=_ok(md5='34e7ec236c4d6d7a00bc5e10af939f76', reg='tasksacktest.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_TASKS':None },
         res=_ok(md5='c3fbb63eea333ea3326f92ec01e19d42', reg='tasksacktest-t.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None },
         res=_ok(md5='031d2c3e545b287b1696e746d7986de9', reg='tasksacktest-s.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None, 'COMPILE_TASKS':None },
         res=_ok(md5='64296327ef40e731545848e5b54c7638', reg='tasksacktest-st.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='f249971ea038f216494699e15dc79c0d', reg='tasksacktest.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_TASKS':None }, glulx=True,
         res=_ok(md5='a63c7ede660b38cc1f89fad0271902b8', reg='tasksacktest-t.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None }, glulx=True,
         res=_ok(md5='5195837e9b38346454d49caeee669732', reg='tasksacktest-s.reg'))

    Test('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None, 'COMPILE_TASKS':None }, glulx=True,
         res=_ok(md5='7dfd62f0a3fabb7fed747bdc4575986c', reg='tasksacktest-st.reg'))


class Run_Coalesce(TestGroup, key='COALESCE'):
    Test('onechar-strings.inf',
         res=_ok(reg='onechar-strings.reg'))

    Test('onechar-strings.inf', glulx=True,
         res=_ok(reg='onechar-strings.reg'))

    Test('onechar-strings.inf', define={ 'BAD_SINGLE_AT':None },
         res=_error())

    Test('onechar-strings.inf', define={ 'BAD_SINGLE_AT':None }, glulx=True,
         res=_error())

    Test('onechar-strings-c1.inf',
         res=_ok(reg='onechar-strings-c1.reg'))

    Test('onechar-strings-c1.inf', glulx=True,
         res=_ok(reg='onechar-strings-c1.reg'))


class Run_CompileOpt(TestGroup, key='COMPILEOPT'):
    # Can't change DICT_WORD_SIZE in Z-code
    Test('optprectest.inf',
         res=_error())
    
    Test('optprectest.inf', glulx=True,
         res=_ok(md5='0b79b2fe693c52f75ab310cbb4e87870'))
    
    Test('optprectest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':12},
         res=_ok(md5='d062bd17ac1c2147186eb4f6334860d2'))
    
    Test('optprectest.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':19},
         res=_ok(md5='bd4294c60002dfb279e59fcdbadf935f'))
    
    Test('optprectest.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':19, 'DICT_WORD_SIZE':12},
         res=_ok(md5='46bfc59140177529e4a6c5b218bde821'))
    
    
class Run_DefineOpt(TestGroup, key='DEFINEOPT'):
    Test('defineopttest.inf',
         res=_ok(md5='dcd9791cac74c6cb01aa837a62cbfe6a'))

    Test('defineopttest.inf', debug=True,
         res=_ok(md5='01512a80ab012a9ef1b4c245050e4f1e'))

    Test('defineopttest.inf', define={ 'DEBUG':None },
         res=_ok(md5='01512a80ab012a9ef1b4c245050e4f1e'))

    Test('defineopttest.inf', define={ 'DEBUG':0 },
         res=_ok(md5='01512a80ab012a9ef1b4c245050e4f1e'))

    Test('defineopttest.inf', define={ 'FOO':26, 'BAR':-923, 'BAZ':None, 'QUUX':123, 'MUM':-1, 'NERTZ':99999 },
         res=_ok(md5='46d9190e220c5b6761b0fa62b7ab0359'))

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
         res=_ok(md5='dcd9791cac74c6cb01aa837a62cbfe6a'))

    Test('defineopttest.inf', define={ 'XFOO':3, 'xfoo':3 },
         res=_ok(md5='dcd9791cac74c6cb01aa837a62cbfe6a'))

    Test('defineopttest.inf', glulx=True,
         res=_ok(md5='8a430050e35bb7ac274ea696d4f12332'))

    Test('defineopttest.inf', glulx=True, debug=True,
         res=_ok(md5='5cbab6dd8f592894f1da3e4c22af524c'))

    Test('defineopttest.inf', glulx=True, define={ 'DEBUG':None },
         res=_ok(md5='5cbab6dd8f592894f1da3e4c22af524c'))

    Test('defineopttest.inf', glulx=True, define={ 'DEBUG':0 },
         res=_ok(md5='5cbab6dd8f592894f1da3e4c22af524c'))

    Test('defineopttest.inf', glulx=True, define={ 'Wordsize':4 },
         res=_ok(md5='8a430050e35bb7ac274ea696d4f12332'))


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
         res=_ok(md5='39e332cb533985f5fd22a76cb1b93b45', md5match='Advent:z', warnings=0, debugfile='38388187e70bd8a40007f53dd08fcb28'))

    Test('Advent.inf', includedir='i6lib-611', debugfile=True, glulx=True,
         res=_ok(md5='3bd969ddadb139f028e9cc6d0d5534cc', md5match='Advent:g', warnings=0, debugfile='1f51de406031f1d8a44377e3351d80d7'))

    Test('Advent.inf', includedir='i6lib-611', debugfile=True, memsettings={'OMIT_SYMBOL_TABLE':1},
         res=_ok(md5='410f302b1e1b0702f8d016d6f31975d0', warnings=0, debugfile='56322b9201b6adebce61ca8df26ee55e'))

    Test('Advent.inf', includedir='i6lib-611', debugfile=True, memsettings={'GRAMMAR_META_FLAG':1},
         res=_ok(md5='be866e8bcf38c83c2be6c4f612ec1f7c', warnings=0, debugfile='228a1ff6652e286b9e4f49a2b562ad37'))

    Test('undefdefault.inf', debugfile=True,
         res=_ok(md5='90866a483312a4359bc00db776e6eed4', warnings=0, debugfile='7af465341b1f20bd9b684e7442468db9'))


class Run_TranscriptFile(TestGroup, key='TRANSCRIPTFILE'):
    Test('Advent.inf', includedir='i6lib-611', transcriptfile=True,
         res=_ok(md5='39e332cb533985f5fd22a76cb1b93b45', md5match='Advent:z', warnings=0, transcriptfile='cea5c49f474a3af53aacc6c62eb71f86'))
    
    Test('Advent.inf', includedir='i6lib-611', transcriptfile=True, memsettings={'TRANSCRIPT_FORMAT':1},
         res=_ok(md5='39e332cb533985f5fd22a76cb1b93b45', md5match='Advent:z', warnings=0, transcriptfile='81c825e994d5ed82b1be9eece7b0f85d'))
    
    Test('Advent.inf', includedir='i6lib-611', transcriptfile=True, glulx=True,
         res=_ok(md5='3bd969ddadb139f028e9cc6d0d5534cc', md5match='Advent:g', warnings=0, transcriptfile='f9a6cec6d2e674ab0f5a6c1b230fb232'))
    
    Test('Advent.inf', includedir='i6lib-611', transcriptfile=True, memsettings={'TRANSCRIPT_FORMAT':1}, glulx=True,
         res=_ok(md5='3bd969ddadb139f028e9cc6d0d5534cc', md5match='Advent:g', warnings=0, transcriptfile='b480ebb779e96d704f60bfc3aeedb785'))
    
    Test('source-encoding-u.inf', transcriptfile=True,
         res=_ok(md5='644bd6e55b30520a182dad4bc3b61a27', reg='source-encoding-u.reg', transcriptfile='f86689cfeb61c9a888164565a8b30734'))

    Test('source-encoding-u.inf', transcriptfile=True, memsettings={'TRANSCRIPT_FORMAT':1},
         res=_ok(md5='644bd6e55b30520a182dad4bc3b61a27', reg='source-encoding-u.reg', transcriptfile='e9cb23cbe92ab2d855730e9244fe78b6'))

    # no reg= for the Glulx versions, because the test case isn't set up for Glulx output
    
    Test('source-encoding-u.inf', transcriptfile=True, memsettings={'DICT_CHAR_SIZE':4}, glulx=True,
         res=_ok(md5='d8ac6c6191086e52fe9206270e86b068', transcriptfile='66d80ad2023df8b1ed3b315ebee0dfde'))

    Test('source-encoding-u.inf', transcriptfile=True, memsettings={'DICT_CHAR_SIZE':4, 'TRANSCRIPT_FORMAT':1}, glulx=True,
         res=_ok(md5='d8ac6c6191086e52fe9206270e86b068', transcriptfile='eb1c8f3aa672125dd1810b91fcfa842b'))

    

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
         res=_ok(md5='7eac2c0c479fb848387ff665fa08dca8', warnings=4, reg='allpass.reg'))

    Test('or_condition_test.inf', glulx=True,
         res=_ok(md5='4260d78dc6d237e6fd70e5a523cf4044', warnings=4, reg='allpass.reg'))


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

    Test('abbrevtest-squiggle.inf', economy=False,
         res=_ok(reg='abbrevtest-squiggle.reg'))

    Test('abbrevtest-squiggle.inf', glulx=True, economy=False,
         res=_ok(reg='abbrevtest-squiggle.reg'))

    Test('abbrevtest-squiggle.inf', economy=True,
         res=_ok(reg='abbrevtest-squiggle.reg'))

    Test('abbrevtest-squiggle.inf', glulx=True, economy=True,
         res=_ok(reg='abbrevtest-squiggle.reg'))

    Test('Advent-abbrev.inf', includedir='i6lib-611', economy=True,
         res=_ok(md5='02f642b1fb24e14522fa7e9d126fde9f', reg='Advent-z.reg'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', glulx=True, economy=True,
         res=_ok(md5='bec3db86580b8bb219369992e504a92d', reg='Advent-g.reg'))
    
    
    
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
         res=_ok(md5='4f2e4a02974e289c9bad777505ea42e0', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':800},
         res=_ok(md5='dd8b5f0a87714ffa9b9cff3c93693c2c', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':10000},
         res=_ok(md5='dd8b5f0a87714ffa9b9cff3c93693c2c', warnings=0, reg='Advent-z.reg'))

    Test('max_inline_string_test.inf',
         res=_ok(warnings=0))

    Test('max_inline_string_test.inf', memsettings={'ZCODE_MAX_INLINE_STRING':999},
         res=_ok(warnings=0))

    Test('max_inline_string_test.inf', memsettings={'ZCODE_MAX_INLINE_STRING':1000},
         res=_error())

    
    
class Run_Max_Abbrevs(TestGroup, key='MAX_ABBREVS'):
    Test('abbrevtest.inf',
         res=_ok(md5='72e89b201c81a95b5fad9bb3a2ba766b'))
    
    Test('abbrevtest.inf', glulx=True,
         res=_ok(md5='5571fb68ce3735314a8d132d35c13cdf'))
    
    Test('abbrevtest.inf', economy=True,
         res=_ok(md5='6d8fe1c12b6058f10edd1190c250a1c5'))
    
    Test('abbrevtest.inf', glulx=True, economy=True,
         res=_ok(md5='443bdf885069cea19b251c7d03866be3'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611',
         res=_ok(md5='39e332cb533985f5fd22a76cb1b93b45', md5match='Advent:z'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='3bd969ddadb139f028e9cc6d0d5534cc', md5match='Advent:g'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', economy=True,
         res=_ok(md5='02f642b1fb24e14522fa7e9d126fde9f'))
    
    Test('Advent-abbrev.inf', includedir='i6lib-611', glulx=True, economy=True,
         res=_ok(md5='bec3db86580b8bb219369992e504a92d'))
    
    Test('i7-min-6G60-abbrev.inf', zversion=8, economy=True,
         res=_ok(md5='07eeab49614b569c002c88ce77d9ac1c', reg='i7-min-6G60.reg'))
    
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
         res=_ok(md5='c19bf11522eb25ff304e32c9537ceae4', warnings=2, reg='unused_verbs_lib.reg'))
    
    Test('unused_verbs_lib.inf', includedir='i6lib-611', glulx=True,
         res=_ok(md5='125ee3c3ec1f503fe988630d21cb3023', warnings=2, reg='unused_verbs_lib.reg'))
    
    
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
         res=_ok(md5='95803b63d07051762ad091c3b4f73877', reg='i7-min-6G60.reg'))

    Test('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True,
         res=_ok(md5='4678a78a83d070e07599f105086f64ec', reg='i7-min-6G60.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='ea36b95f4ae4b9b27073d51de0d04310', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True,
         res=_ok(md5='8095df83b6fb9f88959bb14bb07c6f65', warnings=0, reg='Advent-g.reg'))

    Test('strip_func_test.inf', memsettings={'OMIT_UNUSED_ROUTINES':1},
         res=_ok(md5='07bd8dcf2c8f3a8e544a53584e417ad2'))

    Test('strip_func_test.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True,
         res=_ok(md5='5ebeba63f77407fc175f00055f565933'))


class Run_Omit_Symbol_Table(TestGroup, key='OMIT_SYMBOL_TABLE'):
    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_SYMBOL_TABLE':1},
         res=_ok(md5='410f302b1e1b0702f8d016d6f31975d0', warnings=0, reg='Advent-z.reg'))

    Test('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_SYMBOL_TABLE':1}, glulx=True,
         res=_ok(md5='cd58737aa25c957fa79147aabd3cb5a7', warnings=0, reg='Advent-g.reg'))

    Test('library_of_horror-36.inf', includedir='punylib-36', memsettings={'OMIT_SYMBOL_TABLE':1}, zversion=3,
         res=_ok(md5='0f0557f059a3fa88cf091850d13ae089', reg='library_of_horror.reg'))
    
    Test('omit-symbol-table-test.inf', memsettings={'OMIT_SYMBOL_TABLE':1},
         res=_ok(md5='4098a8d2602bd004f0c727bf547ecab9', warnings=0))

    Test('omit-symbol-table-test.inf', memsettings={'OMIT_SYMBOL_TABLE':1}, glulx=True,
         res=_ok(md5='20f259747209d5d0c01f8e75910d2b38', warnings=0))

    
class Run_ZCode_File_End_Padding(TestGroup, key='ZCODE_FILE_END_PADDING'):
    Test('minimal_test.inf', memsettings={'ZCODE_FILE_END_PADDING':0},
         res=_ok(md5='1847d28cc183ec23c50bd5bca52a1b21'))

    Test('i7-min-6G60.inf', memsettings={'ZCODE_FILE_END_PADDING':0},
         res=_ok(md5='79ff992106e788cb528284389851dbf8', reg='i7-min-6G60.reg'))

    Test('Advent.inf', includedir='i6lib-611', zversion=8,
         res=_ok(md5='7ea18d6a2f7da766cce549cfcaa3b44a', reg='Advent-z.reg'))

    Test('library_of_horror-16.inf', includedir='punylib-16', zversion=3, memsettings={'ZCODE_FILE_END_PADDING':0},
         res=_ok(md5='00e99576ac5b98e79325c624ad7e18b0'))

    Test('library_of_horror-36.inf', includedir='punylib-36', memsettings={'ZCODE_FILE_END_PADDING':0}, zversion=3,
         res=_ok(md5='44cd1518499f351ee85c99f42dee1609', reg='library_of_horror.reg'))


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
         res=_ok(md5='7cf2940254a5aed01c4e176ece935f7d', reg='allpass.reg'))

    Test('compact_array_bug.inf', memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(md5='cc28767ae57867262b756741b332e84c', reg='allpass.reg'))

    
    Test('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(md5='6473a6b9fcf388272a136b30f84db6ab', warnings=0, reg='Advent-z.reg'))

    Test('library_of_horror-36.inf', includedir='punylib-36', zversion=3, memsettings={'ZCODE_COMPACT_GLOBALS':1},
         res=_ok(md5='e9f579e77c21cbfc57811cbd2319737e', reg='library_of_horror.reg'))


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

