#!/usr/bin/env python3

# This script runs the Inform 6 compiler many times, testing for memory
# overflow conditions. It uses the I6 source files in the src directory.
# It also assumes that there's a usable Inform binary in the current
# directory. (If not, supply a --binary argument.)
#
# To run: "python runtest.py".
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
errorlist = []

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
    stdout = stdout.decode()
    stderr = stderr.decode()
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
            error(self, 'Run ended with signal %s' % (signame,))
        else:
            lines = stderr.split('\n')
            for ln in lines:
                inheader = True
                if ('GuardMalloc[' in ln):
                    if (inheader):
                        if re.match('GuardMalloc[^:]*: version [0-9.]*', ln):
                            inheader = False
                        continue
                    error(self, 'Apparent libgmalloc error ' + ln)
            
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
                    error(self, 'Compiler error')
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
                    error(self, 'Unmatched "Compiled" line in output: ' + ln)
                    continue

            if (outlines > 1):
                error(self, 'Too many "Compiled" lines in output')

            if (retcode == 0):
                self.status = Result.OK
                if (self.errors):
                    error(self, 'Run status zero despite %d errors' % (self.errors,))
            else:
                self.status = Result.ERROR
                if (not self.errors):
                    error(self, 'Run status nonzero despite no errors')

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

    def canonical_checksum(self):
        """ Load a file and construct an MD5 checksum, allowing for
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

    def is_ok(self, md5=None, reg=None, abbreviations=None, warnings=None):
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
        """
        if (self.status == Result.OK):
            if not os.path.exists(self.filename):
                error(self, 'Game file does not exist: %s' % (self.filename,))
                print('*** TEST FAILED ***')
                return False
            # Any or all of the following could fail.
            isok = True
            if md5 or opts.checksum:
                val = self.canonical_checksum()
                if opts.checksum:
                    print('--- checksum:', val)
                if md5 and val != md5:
                    error(self, 'Game file mismatch: %s is not %s' % (val, md5,))
                    print('*** TEST FAILED ***')
                    isok = False
            if abbreviations is not None:
                s1 = set(abbreviations)
                s2 = set(self.abbreviations)
                if s1 != s2:
                    error(self, 'Abbreviations list mismatch: missing %s, extra %s' % (list(s1-s2), list(s2-s1),))
                    print('*** TEST FAILED ***')
                    isok = False
            if warnings is not None:
                if self.warnings != warnings:
                    error(self, 'Warnings mismatch: expected %s but got %s' % (warnings, self.warnings,))
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
            return isok
        error(self, 'Should be ok, but was: %s' % (self,))
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
        error(self, 'Should be error (%s), but was: %s' % (val, self,))
        print('*** TEST FAILED ***')
        return False

    def is_error(self, warnings=None, errors=None):
        """ Assert that the compile failed, but *not* with an
        "increase $SETTING" error.
        """
        if (self.status == Result.ERROR and not self.memsetting):
            if errors is not None:
                if self.errors != errors:
                    error(self, 'Errors mismatch: expected %s but got %s' % (errors, self.errors,))
                    print('*** TEST FAILED ***')
                    return False
            if warnings is not None:
                if self.warnings != warnings:
                    error(self, 'Warnings mismatch: expected %s but got %s' % (warnings, self.warnings,))
                    print('*** TEST FAILED ***')
                    return False
            return True
        error(self, 'Should be error, but was: %s' % (self,))
        print('*** TEST FAILED ***')
        return False

    def run_regtest(self, reg):
        regfile = os.path.join('reg', reg)
        if not os.path.exists(regfile):
            error(self, 'Regression test file does not exist: %s' % (regfile,))
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
            error(self, 'Regression test failed: %s\n%s' % (regfile, errtext))
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
    
def error(res, msg):
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

# And now, the tests themselves.

def run_checksum_test():
    res = compile('minimal_test.inf')
    res.is_ok(md5='90866a483312a4359bc00db776e6eed4', warnings=0)

    res = compile('minimal_test.inf', zversion=3)
    res.is_ok(md5='6143c98e20a44d843c1a6fbe2c19ecae')

    res = compile('minimal_test.inf', zversion=4)
    res.is_ok(md5='f82709a196ebbefe109525084220c35a')

    res = compile('minimal_test.inf', zversion=5)
    res.is_ok(md5='90866a483312a4359bc00db776e6eed4')

    res = compile('minimal_test.inf', zversion=6)
    res.is_ok(md5='08b59209daa947437a5119b8060522ef')

    res = compile('minimal_test.inf', zversion=6, bigmem=True)
    res.is_ok(md5='e273d746baf6dac4324c95e45982bec0')

    res = compile('minimal_test.inf', zversion=7)
    res.is_ok(md5='26bd70faebf8c61638a736a72f57c7ad')

    res = compile('minimal_test.inf', zversion=7, bigmem=True)
    res.is_ok(md5='814c9ac5777674f1cc98f9a0cd22d6da')

    res = compile('minimal_test.inf', zversion=8)
    res.is_ok(md5='fa7fc9bbe032d27355b0fcf4fb4f2c53')

    res = compile('minimal_test.inf', glulx=True)
    res.is_ok(md5='6e647107c3b3c46fc9556da0330db3a6', warnings=0)
    
    res = compile('glulxercise.inf', glulx=True)
    res.is_ok(md5='6a90d7ed9f172551f88950dc91412d5a', warnings=0)
    
    res = compile('i7-min-6G60.inf')
    res.is_ok(md5='c41a13473d6b01990bb0e781f8ac575c', reg='i7-min-6G60.reg')

    res = compile('i7-min-6G60.inf', zversion=8)
    res.is_ok(md5='16d41aba696f3b6ea4810782bba9528e', reg='i7-min-6G60.reg')

    res = compile('i7-min-6G60.inf', glulx=True)
    res.is_ok(md5='e9735da155ab0c720e73f6be3b83bf48', reg='i7-min-6G60.reg')

    res = compile('i7-min-6M62-z.inf', zversion=8)
    res.is_ok(md5='7ec56a1fd21c2e0d0e47a16af1459c4d', reg='i7-min-6M62.reg')

    res = compile('i7-min-6M62-g.inf', glulx=True)
    res.is_ok(md5='83e7089561cde53a16e1c09e9fcdb2dc', reg='i7-min-6M62.reg')

    res = compile('Advent.inf', includedir='i6lib-611')
    res.is_ok(md5='253056d3e169c9c3d871525918260eb3', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8)
    res.is_ok(md5='91ceadaf4e9077a111941a27f342a4dd', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True)
    res.is_ok(md5='b2bb42f3ff9b001cb11238bcbd3ae0f5', warnings=0, reg='Advent-g.reg')

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8, strict=False)
    res.is_ok(md5='869493d777aa62e75d34692f61ba18c0', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True, strict=False)
    res.is_ok(md5='5e17c8d40fdf2af1c48fed04018f8808', warnings=0, reg='Advent-g.reg')

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8, debug=True)
    res.is_ok(md5='a09b6553f002d932839edf68061c941e', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True, debug=True)
    res.is_ok(md5='c2582674fc423437c922a4873f123d2b', warnings=0, reg='Advent-g.reg')

    res = compile('Advent.inf', includedir='i6lib-611', infix=True)
    res.is_ok(md5='2d3e5c119619459877934f9211f6cabd', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-6.12.6')
    res.is_ok(md5='21074a2a0b2f5edc46b2c651cf68fa8f', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-6.12.6', glulx=True)
    res.is_ok(md5='744f86ec3f3587a037720906b49cdcb4', warnings=1)

    res = compile('box_quote_test.inf', includedir='i6lib-611')
    res.is_ok(md5='074dbc09049827fc021885cf256c7616', warnings=0)

    res = compile('cloak-metro84-v3test.inf', zversion=3, economy=False)
    res.is_ok(md5='cc592023294af1d6a62c42db6e9533d8', warnings=2, reg='cloak-metro84.reg')

    res = compile('cloak-metro84-v3test.inf', zversion=4, economy=False)
    res.is_ok(md5='ee15a03257a469e92b8d56aa70dc17f3', warnings=2, reg='cloak-metro84.reg')

    res = compile('cloak-metro84-v3test.inf', zversion=5, economy=False)
    res.is_ok(md5='dac502dd34a5d650db461b42112b7d37', warnings=2, reg='cloak-metro84.reg')

    res = compile('cloak-metro84-v3test.inf', zversion=3, economy=True)
    res.is_ok(md5='2d82da285726122670136030447e9b68', warnings=2, reg='cloak-metro84.reg')

    res = compile('cloak-metro84-v3test.inf', zversion=4, economy=True)
    res.is_ok(md5='3a6c60e98e34f98dfd9b821881a8cbca', warnings=2, reg='cloak-metro84.reg')

    res = compile('cloak-metro84-v3test.inf', zversion=5, economy=True)
    res.is_ok(md5='33fc9aa736d5fb97dd6adde04b8689a0', warnings=2, reg='cloak-metro84.reg')

    res = compile('library_of_horror-16.inf', includedir='punylib-16', zversion=3)
    res.is_ok(md5='3ebaded1f6f33f0ec3e82bcd8b8e858c')

    res = compile('library_of_horror-16.inf', includedir='punylib-16', zversion=3, memsettings={'OMIT_UNUSED_ROUTINES':1})
    res.is_ok(md5='d5b29e6eb2d8f1bc9083f04e0cdd58e9')

    # OMIT_UNUSED_ROUTINES is set in the source
    res = compile('library_of_horror-36.inf', includedir='punylib-36', zversion=3)
    res.is_ok(md5='eb4ef5320f716e2fa14fd8a4a061950a', reg='library_of_horror.reg')


def run_dict_test():
    res = compile('dict-size-v3test.inf', zversion=3)
    res.is_ok(md5='f75ed33c64fbba8a53a1a02a1cbeea2b', reg='allpass.reg')

    res = compile('dict-size-v3test.inf', zversion=5)
    res.is_ok(md5='58fe6d80014bb250362990e21fef40c5', reg='allpass.reg')

    res = compile('dict-cutoff-v3test.inf', strict=False, zversion=3)
    res.is_ok(md5='4f32fb4f78295fe33bcfe1396b2a5e98', reg='allpass.reg')

    res = compile('dict-cutoff-v3test.inf', strict=False, zversion=4)
    res.is_ok(md5='e5bf355441d5e5f36c8994f733bb8a8a', reg='allpass.reg')

    res = compile('dict-cutoff-v3test.inf', strict=False, zversion=5)
    res.is_ok(md5='06625ab421e9c4b6915658f5fdfbc80d', reg='allpass.reg')

    # This messes with the alphabet, which changes the output.
    res = compile('dict-cutoff-alttest.inf', strict=False, zversion=4)
    res.is_ok(md5='d09f4ce77d4a4d197c3b553ef62d7d46', reg='dict-cutoff-alttest-v4.reg')

    res = compile('dict-cutoff-alttest.inf', strict=False, zversion=5)
    res.is_ok(md5='9a3b2476db96afe36f46a7360db3150d', reg='allpass.reg')

    res = compile('dict-cutoff-alttest.inf', strict=False, zversion=8)
    res.is_ok(md5='a7bbc5992810c2321a3d8273c8a9d02d', reg='allpass.reg')

    res = compile('max_dict_entries.inf')
    res.is_ok()

    res = compile('max_dict_entries.inf', glulx=True)
    res.is_ok()

    res = compile('dict-entry-size-test.inf', zversion=3, strict=False)
    res.is_ok(md5='015b14adf6ed2653cc61f1c57eadbcbc')

    # The checksum here is different because the "Version 3" directive doesn't work perfectly
    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, define={'EARLYDEF':None}, versiondirective=True)
    res.is_ok(md5='5df7a75b03a530d06397fbc51a58133c')

    # Cannot put Version directive at the end
    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, define={'LATEDEF':None}, versiondirective=True)
    res.is_error()

    # Warning about "Dictionary 'w' x y" directive
    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1}, define={'TRYDICT3':None})
    res.is_ok(warnings=1)

    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, define={'TRYVERB':None})
    res.is_ok()

    # Cannot use GV1 with ZCODE_LESS_DICT_DATA
    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1}, define={'TRYVERB':None})
    res.is_error()

    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, define={'TRYPAR3':None})
    res.is_ok()

    # Cannot use #dict_par3 with ZCODE_LESS_DICT_DATA
    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1}, define={'TRYPAR3':None})
    res.is_error()

    res = compile('dict-entry-size-test.inf', zversion=3, strict=False, memsettings={'ZCODE_LESS_DICT_DATA':1})
    res.is_ok(md5='ff7005f93c1ff23adb38eb83e47df385')

    res = compile('dict-entry-size-test.inf', zversion=5)
    res.is_ok(md5='83fe325758d4c092f0046f29eb224f5e')

    res = compile('dict-entry-size-test.inf', zversion=5, memsettings={'ZCODE_LESS_DICT_DATA':1})
    res.is_ok(md5='ae0d2c46bd7e1986d37359e748e4596c')

    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_LESS_DICT_DATA':1})
    res.is_ok(md5='3579ad9300d2414a6b60343fe254b4b9', warnings=0, reg='Advent-z.reg')

    res = compile('dict-sysconst-test.inf')
    res.is_ok(md5='9e7686c1d206eaedca2da668dbefaa1f', reg='allpass.reg')

    res = compile('dictlongflagtest.inf')
    res.is_ok(md5='0d78b9f9117afe5be3047a911b0a0952')

    res = compile('dictlongflagtest.inf', zversion=3)
    res.is_ok(md5='22c158dc4fb8feb61f4cd6fc5983041c')

    res = compile('dictlongflagtest.inf', glulx=True)
    res.is_ok(md5='cc6c969d085fae001fde77c335973e28')

    res = compile('dictlongflagtest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':10})
    res.is_ok(md5='fd13c0fbcf994af91342ea3d6d65a0ff')

    res = compile('dictlongflagtest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':11})
    res.is_ok(md5='a55c2608cfbd93eedbeaec99c24d85bd')

    res = compile('dictlongflagtest.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4})
    res.is_ok(md5='eec2db33148b1f95660823a5b9e97482')

    res = compile('dictlongflagtest.inf', define={'BADFLAG':None})
    res.is_ok(md5='ca030580d46f2caf4f572c059540aab8')
    
    res = compile('dictlongflagtest.inf', glulx=True, define={'BADFLAG':None})
    res.is_ok(md5='3b79154a39bb1e11e6d21b40b158110b')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0})
    res.is_ok(md5='7c7ef0506b467dd94b6615c6da88fcff')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, zversion=3)
    res.is_ok(md5='1bfad5368945e03d4c71d2a34eea9912')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True)
    res.is_ok(md5='d38418d3900bd545dfb5bab3eebd222e')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_WORD_SIZE':10}, glulx=True)
    res.is_ok(md5='794b616e86813b0d396b4e8e845b120f')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_WORD_SIZE':11}, glulx=True)
    res.is_ok(md5='70ddb5e68b3a28aaf9b68a424b891a98')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_CHAR_SIZE':4}, glulx=True)
    res.is_ok(md5='c0e051373b7affadd68e50001faabc8c')

    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, define={'BADFLAG':None})
    res.is_error()
    
    res = compile('dictlongflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True, define={'BADFLAG':None})
    res.is_error()

    res = compile('i7-min-6M62-z.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, zversion=8)
    res.is_ok(md5='1d5f5aebf09a10ea18983fa9446dea97', reg='i7-min-6M62.reg')

    res = compile('i7-min-6M62-g.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True)
    res.is_ok(md5='1d1494a4498275c2c9057c3557c46e72', reg='i7-min-6M62.reg')

    res = compile('dictnewflagtest.inf')
    res.is_ok(md5='6a46be13dad0cb7ea0bb3b055427615a')
    
    res = compile('dictnewflagtest.inf', glulx=True)
    res.is_ok(md5='097c61acb854a80cfb2fd5cae9e72d48')
    
    res = compile('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0})
    res.is_ok(md5='79b88af5e431f59ddea6bbb28d47ffd8')
    
    res = compile('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0}, glulx=True)
    res.is_ok(md5='b8b2c4ca7553a85b69ca5435a6a5cee7')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_IMPLICIT_SINGULAR':1})
    res.is_ok(md5='8ce940f818408b04c8cd3e6c05119b1f')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_IMPLICIT_SINGULAR':1}, glulx=True)
    res.is_ok(md5='ee0a007647fa8f58f2358665fe93e744')
    
    res = compile('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_IMPLICIT_SINGULAR':1})
    res.is_ok(md5='537f36822afb31ab7cfa8c503ea965a5')
    
    res = compile('dictnewflagtest.inf', memsettings={'LONG_DICT_FLAG_BUG':0, 'DICT_IMPLICIT_SINGULAR':1}, glulx=True)
    res.is_ok(md5='2acd0a25997ca335b5ae07a9bd4e4561')
    
    res = compile('dictnewflagtest.inf', define={'BADFLAG1':None})
    res.is_error()
    
    res = compile('dictnewflagtest.inf', define={'BADFLAG2':None})
    res.is_error()
    
    res = compile('dictnewflagtest.inf', glulx=True, define={'BADFLAG1':None})
    res.is_error()
    
    res = compile('dictnewflagtest.inf', glulx=True, define={'BADFLAG2':None})
    res.is_error()
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1})
    res.is_ok(md5='05ca1b8acf37340582c8fb075eb3f14a')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1}, glulx=True)
    res.is_ok(md5='6d2fae4684f6f17b93341588fd407e7d')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'LONG_DICT_FLAG_BUG':0})
    res.is_ok(md5='41c779bc75fad0e85703fd2b9bc14912')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'LONG_DICT_FLAG_BUG':0}, glulx=True)
    res.is_ok(md5='a5d8c864a7400e349f32e8261deba92d')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'DICT_IMPLICIT_SINGULAR':1, 'LONG_DICT_FLAG_BUG':1, 'DICT_WORD_SIZE':10}, glulx=True)
    res.is_ok(md5='d3def326e708a7848c7257696e74f518')
    
    res = compile('dictnewflagtest.inf', memsettings={'DICT_TRUNCATE_FLAG':1, 'DICT_IMPLICIT_SINGULAR':1, 'LONG_DICT_FLAG_BUG':0, 'DICT_WORD_SIZE':10}, glulx=True)
    res.is_ok(md5='d3def326e708a7848c7257696e74f518')
    
    res = compile('Advent.inf', includedir='i6lib-611w,i6lib-611')
    res.is_ok(md5='88bf1fa056adc0e6b9508e70d09a420a', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611w,i6lib-611', glulx=True)
    res.is_ok(md5='f0ca486fa1d9f8012eae29a89d800474', warnings=0, reg='Advent-g.reg')

    res = compile('dictlargeentrytest.inf', glulx=True)
    res.is_ok(md5='aa96bddd17fc8fbe78871d9f4088df1a', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_CHAR_SIZE':4})
    res.is_ok(md5='70c228f06ee6b3c5af55851480141437', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':30})
    res.is_ok(md5='e690c593b10fde1dd87a3498007452be', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':30, 'DICT_CHAR_SIZE':4})
    res.is_ok(md5='457a3de16ef58dc96056e090c97fcabc', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':35})
    res.is_ok(md5='cf5c66f2e71b1660a5a78b8ad6968d5d', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':35, 'DICT_CHAR_SIZE':4})
    res.is_ok(md5='19116031757220e8fa01b1d88aadd664', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':144})
    res.is_ok(md5='b19c63f5ed6e8738b84aa6889daf5d85', reg='allpass.reg')
    
    res = compile('dictlargeentrytest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':144, 'DICT_CHAR_SIZE':4})
    res.is_ok(md5='d42460263e3fe758098c7b975f994239', reg='allpass.reg')
    

def run_grammar_test():
    # File compiles the same whether the grammar version is set by Constant or compiler option
    
    res = compile('grammar-version-test.inf')
    res.is_ok(md5='d9dfd1f956beeeff947a30c4617dab48')

    res = compile('grammar-version-test.inf', define={'SET_GV_1':None})
    res.is_ok(md5='d9dfd1f956beeeff947a30c4617dab48')

    res = compile('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':1})
    res.is_ok(md5='d9dfd1f956beeeff947a30c4617dab48')

    res = compile('grammar-version-test.inf', define={'SET_GV_2':None})
    res.is_ok(md5='d0c7c637051334c0886d4ea1500837f2')

    res = compile('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':2})
    res.is_ok(md5='d0c7c637051334c0886d4ea1500837f2')

    res = compile('grammar-version-test.inf', glulx=True)
    res.is_ok(md5='d47bae32d9bd18f7f2dbd80577795398')

    res = compile('grammar-version-test.inf', glulx=True, define={'SET_GV_2':None})
    res.is_ok(md5='d47bae32d9bd18f7f2dbd80577795398')

    res = compile('grammar-version-test.inf', glulx=True, memsettings={'GRAMMAR_VERSION':2})
    res.is_ok(md5='d47bae32d9bd18f7f2dbd80577795398')

    res = compile('grammar-version-test.inf', define={'SET_GV_3':None})
    res.is_ok(md5='4516571efb9e088b090f6e7536a7031a')

    res = compile('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':3})
    res.is_ok(md5='4516571efb9e088b090f6e7536a7031a')

    res = compile('grammar-version-test.inf', glulx=True, define={'SET_GV_3':None})
    res.is_error()

    res = compile('grammar-version-test.inf', glulx=True, memsettings={'GRAMMAR_VERSION':3})
    res.is_error()

    res = compile('grammar-version-test.inf', define={'SET_GV_4':None})
    res.is_error()

    res = compile('grammar-version-test.inf', memsettings={'GRAMMAR_VERSION':4})
    res.is_error()

    res = compile('grammar-version-test.inf', glulx=True, define={'SET_GV_4':None})
    res.is_error()

    res = compile('grammar-version-test.inf', glulx=True, memsettings={'GRAMMAR_VERSION':4})
    res.is_error()

    # Fake_Action before Grammar__Version 2
    res = compile('grammar-version-test.inf', define={'EARLY_FAKE_ACTION':None, 'SET_GV_2':None})
    res.is_error()

    # Real action before Grammar__Version 2
    res = compile('grammar-version-test.inf', define={'EARLY_ACTION_VERB':None, 'SET_GV_2':None})
    res.is_error()

    # ##Action before Grammar__Version 2
    res = compile('grammar-version-test.inf', define={'EARLY_ACTION_CONST':None, 'SET_GV_2':None})
    res.is_ok()

    # action-case before Grammar__Version 2
    res = compile('grammar-version-test.inf', define={'EARLY_ACTION_CASE':None, 'SET_GV_2':None})
    res.is_ok()

    # Same as i7-min-6G60.inf, except we set the grammar by option
    res = compile('i7-min-6G60-gvopt.inf')
    res.is_ok(md5='c41a13473d6b01990bb0e781f8ac575c', reg='i7-min-6G60.reg')

    # Advent with GRAMMAR_META_FLAG should run correctly
    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'GRAMMAR_META_FLAG':1})
    res.is_ok(md5='fd6237f501b101a2d846f6f9f6717401', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True, memsettings={'GRAMMAR_META_FLAG':1})
    res.is_ok(md5='77778a1834ec66ef7f1db3566cb3ed87', warnings=0, reg='Advent-g.reg')

    # Requires GRAMMAR_META_FLAG
    res = compile('grammar-metaflag-test.inf')
    res.is_error()

    res = compile('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1})
    res.is_ok(md5='0746eedd27e4d9b0d5c03e88b55cf533', reg='allpass.reg')

    res = compile('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1, 'GRAMMAR_VERSION':2})
    res.is_ok(md5='f8fa741c80cdc86af9ee2d3c987d54db', reg='allpass.reg')

    res = compile('grammar-metaflag-test.inf', memsettings={'GRAMMAR_META_FLAG':1}, glulx=True)
    res.is_ok(md5='b00bcb640c314ca7e28571deadfc6612', reg='allpass.reg')

    # Compile with the GV3 parser.
    res = compile('Advent.inf', includedir='i6lib-611gv3,i6lib-611')
    res.is_ok(md5='653e053b87a32c36c286b14a021cff05', warnings=0, reg='Advent-z.reg')

    # Compile with the modified parser; meta verbs should be meta.
    res = compile('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', memsettings={'GRAMMAR_META_FLAG':1}, debug=True)
    res.is_ok(md5='5b8b91439c15a69083fa3e99b14567c4', warnings=0)
    
    res = compile('withdaemon.inf', includedir='i6lib-611meta,i6lib-611', memsettings={'GRAMMAR_META_FLAG':1}, debug=True, glulx=True)
    res.is_ok(md5='7b727879c043c5a18e189c8a6091e1d8', warnings=0)

    # All of the following should compile the same.
    res = compile('verbclash.inf', includedir='i6lib-611', define={'EXTENDLAST':None})
    res.is_ok(md5='360072f8688e9f1ad5c44e9ccdc81b51', warnings=0)
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'EXACTSAME':None})
    res.is_ok(md5='360072f8688e9f1ad5c44e9ccdc81b51', warnings=1)
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'CASESAME':None})
    res.is_ok(md5='360072f8688e9f1ad5c44e9ccdc81b51', warnings=1)
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'TRUNCSAME':None})
    res.is_ok(md5='360072f8688e9f1ad5c44e9ccdc81b51', warnings=1)
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'DIFFERENTVERBS1':None})
    res.is_error()
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'DIFFERENTVERBS2':None})
    res.is_error()
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'DIFFERENTVERBS3':None})
    res.is_error()
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'NOVERBS':None})
    res.is_error()
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'NOTAVERB':None})
    res.is_error()
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'BADEQUALS':None})
    res.is_error()
    
    res = compile('verbclash.inf', includedir='i6lib-611', define={'BADEQUALS2':None})
    res.is_error()
    
    
def run_lexer_test():
    res = compile('long_identifier_test.inf')
    res.is_ok()

    res = compile('long_identifiers_2.inf')
    res.is_ok()

    res = compile('long_identifiers_2.inf', glulx=True)
    res.is_ok()

    # Object short names are over 765 Z-chars
    res = compile('long_identifiers_3.inf')
    res.is_memsetting('MAX_SHORT_NAME_LENGTH')

    res = compile('long_identifiers_3.inf', glulx=True)
    res.is_ok()

    res = compile('long_dictword_test.inf')
    res.is_ok()

    res = compile('unclosed_double_quote.inf')
    res.is_error()

    res = compile('unclosed_single_quote.inf')
    res.is_error()

    res = compile('unclosed_double_quote.inf')
    res.is_error()

    res = compile('empty_single_quotes.inf')
    res.is_error()

    res = compile('one_quote_single_quotes.inf')
    res.is_ok()

    res = compile('linebreak-unix.inf')
    res.is_ok(md5='c6141b8c15f81e3d1db728e5aaf1303b', warnings=1)

    res = compile('linebreak-oldmac.inf')
    res.is_ok(md5='c6141b8c15f81e3d1db728e5aaf1303b', warnings=1)

    res = compile('linebreak-dos.inf')
    res.is_ok(md5='c6141b8c15f81e3d1db728e5aaf1303b', warnings=1)

    res = compile('icl-linebreak-unix.inf', glulx=True)
    res.is_ok(md5='3067f025bcc31115e5ec7397761e2f41')

    res = compile('icl-linebreak-dos.inf', glulx=True)
    res.is_ok(md5='3067f025bcc31115e5ec7397761e2f41')

    res = compile('icl-linebreak-oldmac.inf', glulx=True)
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('bad_global.inf')
    res.is_error()

    
def run_directives_test():
    # md5 checks for serial.inf are useless because the checksummer ignores the serial number. Run the compiled file to check it.
    
    res = compile('serial.inf', define={'SETFIXEDSERIAL':None, 'CHECKYEAR':12, 'CHECKMONTH':34, 'CHECKDAY':56})
    res.is_ok(reg='serial-1.reg')
    
    res = compile('serial.inf', define={'SETFIXEDSERIAL':None, 'CHECKYEAR':12, 'CHECKMONTH':34, 'CHECKDAY':56}, glulx=True)
    res.is_ok(reg='serial-1.reg')
    
    res = compile('serial.inf', memsettings={'SERIAL':234567}, define={'CHECKYEAR':23, 'CHECKMONTH':45, 'CHECKDAY':67})
    res.is_ok(reg='serial-2.reg')
    
    res = compile('serial.inf', memsettings={'SERIAL':234567}, define={'CHECKYEAR':23, 'CHECKMONTH':45, 'CHECKDAY':67}, glulx=True)
    res.is_ok(reg='serial-2.reg')
    
    res = compile('serial.inf', define={'SETBADSERIAL1':None})
    res.is_error()
    
    res = compile('serial.inf', define={'SETBADSERIAL2':None})
    res.is_error()
    
    res = compile('staticarraytest.inf')
    res.is_ok(md5='23fed66fd87f9b95586af51afd27fd00')

    res = compile('staticarraytest.inf', glulx=True)
    res.is_ok(md5='29abadec278f29e1c0b5eea0fd9c3495')

    res = compile('undefdirectivetest.inf')
    res.is_ok(md5='de2f2e32f82bf14a4178f3a992762e6b')

    res = compile('undefdirectivetest.inf', glulx=True)
    res.is_ok(md5='b981cf8a2508c9d56b7c4593ac336048')

    res = compile('no-main.inf')
    res.is_error()

    res = compile('no-main.inf', define={'WRONGMAIN':None})
    res.is_error()
    
    res = compile('no-main.inf', define={'FORWARDMAIN':None})
    res.is_error()
    
    res = compile('no-main.inf', glulx=True)
    res.is_error()

    res = compile('no-main.inf', glulx=True, define={'WRONGMAIN':None})
    res.is_error()

    res = compile('no-main.inf', glulx=True, define={'FORWARDMAIN':None})
    res.is_error()

    res = compile('replacerenametest.inf', includedir='src')
    res.is_ok(md5='20f77c3bc7002792f218a345f547b91c')

    res = compile('replacerenametest.inf', includedir='src', glulx=True)
    res.is_ok(md5='0a1fc0c94e71b42e406d8401517636d4')

    res = compile('replacerecursetest.inf')
    res.is_ok(md5='9b89cd42cd723d4fb5197a6276e595c0')

    res = compile('replacerecursetest.inf', glulx=True)
    res.is_ok(md5='2382f2a66978bdd09e42825bdeb551aa')

    res = compile('dictflagtest.inf')
    res.is_ok(md5='6a9dbacc4efc4f13d07ddcea846b5f58')

    res = compile('dictflagtest.inf', glulx=True)
    res.is_ok(md5='05d9526ea9c2bc9bf5fdb41c9e3024e1')

    res = compile('actionextension.inf')
    res.is_ok(md5='8434dd954b155675ec9a853052b5a5bc')

    res = compile('actionextension.inf', glulx=True)
    res.is_ok(md5='7d4bc338e99a777534f03d1a80388e58')

    res = compile('internaldirecttest.inf')
    res.is_ok(md5='7fad50ebab77f541f12e51eb864ad594')

    res = compile('internaldirecttest.inf', glulx=True)
    res.is_ok(md5='8f7bef97e18c912ec45760b57de6fa66')

    res = compile('ifelsedirecttest.inf')
    res.is_ok(md5='ebdbb9f121b45bcfc54a41c71d87c029')

    res = compile('ifelsedirecttest.inf', glulx=True)
    res.is_ok(md5='c0724fca3f6783e10f7188ca4dbb1d3d')

    res = compile('ifdef_vn_test.inf')
    res.is_ok(md5='45f86d7b6218cace38b16f2ca08e8d71')

    res = compile('ifdef_vn_test.inf', glulx=True)
    res.is_ok(md5='5ad58c728862dce11b17d7a93adaaa51')

    res = compile('classordertest.inf')
    res.is_ok(md5='334ef7ef87df98ed6f3b1dd99829deeb', reg='allpass.reg')

    res = compile('classordertest.inf', glulx=True)
    res.is_ok(md5='4025856ed2133af211feda4aa187d1fe', reg='allpass.reg')

    res = compile('classcopytest.inf')
    res.is_ok(md5='4c53497c6c9a93e3163db0b619d9e1f6', reg='allpass.reg')

    res = compile('classcopytest.inf', glulx=True)
    res.is_ok(md5='9f6c50b53599e2a3dec440715759877d', reg='allpass.reg')

    res = compile('forwardproptest.inf')
    res.is_ok(md5='d2a0621f1b3703523a9e0e00da8270d6', reg='allpass.reg')

    res = compile('forwardproptest.inf', strict=False)
    res.is_ok(md5='b181a2d7edd1d8188e0575767f53a886', reg='allpass.reg')

    res = compile('forwardproptest.inf', glulx=True)
    res.is_ok(md5='95095b05c3e5d9765822da3b725a108d', reg='allpass.reg')

    res = compile('forwardproptest.inf', glulx=True, strict=False)
    res.is_ok(md5='82029b0f66f3536734d46ea80c1dab6c', reg='allpass.reg')

    res = compile('indivproptest.inf')
    res.is_ok(md5='fa04f51e34f31a52fb764fab498a620f', reg='allpass.reg')

    res = compile('indivproptest.inf', define={'DEF_INDIV1':None})
    res.is_ok(md5='fa04f51e34f31a52fb764fab498a620f', reg='allpass.reg')

    res = compile('indivproptest.inf', define={'DEF_INDIV2':None})
    res.is_ok(md5='3d4a3fdc6ff5ca44599c7b62f155c614', reg='allpass.reg')

    res = compile('indivproptest.inf', define={'DEF_INDIV1':None,'DEF_INDIV2':None})
    res.is_ok(md5='cde12cbf22e618d63a345a8995199686', reg='allpass.reg')

    res = compile('indivproptest.inf', glulx=True)
    res.is_ok(md5='fe01898bcf2f6b7639be92c213706252', reg='allpass.reg')

    res = compile('indivproptest.inf', define={'DEF_INDIV1':None}, glulx=True)
    res.is_ok(md5='fe01898bcf2f6b7639be92c213706252', reg='allpass.reg')

    res = compile('indivproptest.inf', define={'DEF_INDIV2':None}, glulx=True)
    res.is_ok(md5='3e61c800eaeebbe7fc668acda9bf1be9', reg='allpass.reg')

    res = compile('indivproptest.inf', define={'DEF_INDIV1':None,'DEF_INDIV2':None}, glulx=True)
    res.is_ok(md5='bda9d7dcc34ea1d463b336852a6d515b', reg='allpass.reg')

    res = compile('indivproptest_2.inf')
    res.is_ok(md5='93d8d451f9d7fe20ee127c242e0a39bd', warnings=0, reg='allpass.reg')

    res = compile('indivproptest_2.inf', define={'LONG_PROP_WARN':None})
    res.is_ok(md5='93d8d451f9d7fe20ee127c242e0a39bd', warnings=1, reg='allpass.reg')

    res = compile('indivproptest_2.inf', glulx=True)
    res.is_ok(md5='7e806bf207e3618424ad493ac7d187e7', warnings=0, reg='allpass.reg')

    res = compile('indivproptest_2.inf', define={'LONG_PROP_WARN':None}, glulx=True)
    res.is_ok(md5='7e806bf207e3618424ad493ac7d187e7', warnings=1, reg='allpass.reg')

    res = compile('max_link_directive_length.inf')
    res.is_error()

    res = compile('linkimport.inf')
    res.is_ok()

    res = compile('linkimport.inf', define={'TRY_LINK':None})
    res.is_error()

    res = compile('linkimport.inf', define={'TRY_IMPORT':None})
    res.is_error()

    res = compile('globalarray.inf')
    res.is_ok()

    res = compile('globalarray.inf', glulx=True)
    res.is_ok()

    res = compile('globalarray.inf', define={'USE_GLOBAL_BEFORE_DEF':None})
    res.is_error()

    res = compile('globalarray.inf', define={'DEFINE_GLOBAL_TWICE':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_GLOBAL_NONSYMBOL':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_GLOBAL_STATIC':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_TEMPGLOB':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_GLOBAL_EXTRA':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_GLOBAL_NOVALUE':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_GLOBAL_ARRAY':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_ARRAY_NO_DEF':None})
    res.is_error()
    
    res = compile('globalarray.inf', define={'DEFINE_ARRAY_EXTRA':None})
    res.is_error()
    
    res = compile('globalredef.inf')
    res.is_ok()

    res = compile('globalredef.inf', glulx=True)
    res.is_ok()

    res = compile('unterm-array-test.inf')
    res.is_error(errors=2)


def run_veneer_test():
    res = compile('obj_prop_call.inf')
    res.is_ok()
    
    res = compile('obj_prop_call.inf', zversion=3)
    res.is_error()
    
    res = compile('obj_prop_call.inf', zversion=3, define={'REPLACE_TWO':None})
    res.is_ok()

    res = compile('base_class_prop.inf', zversion=3, includedir='punylib-36')
    res.is_ok(md5='ac96ab44530c68478cec38c5a1049658')
    
    res = compile('base_class_prop.inf', zversion=5, includedir='punylib-36')
    res.is_ok(md5='4bde4d78c2be61dfbb2cd90b58091955')
    
    res = compile('base_class_prop_2.inf', zversion=3, includedir='punylib-36')
    res.is_ok(md5='aed71b23888e763a82ff545dadba88ba')
    
    res = compile('base_class_prop_2.inf', zversion=5, includedir='punylib-36')
    res.is_ok(md5='86a05a59183f723f31c246e070e21a05')
    
    res = compile('obj_prop_test.inf')
    res.is_ok(md5='f3f44fe9d6d31f8f792ee8cf6a6b2dbb')
    
    res = compile('obj_prop_test.inf', strict=False)
    res.is_ok(md5='d8a86fa431147b37e93ffc5c891925a3')
    
    res = compile('obj_prop_test.inf', zversion=3)
    res.is_ok(md5='06f87532155ea09e49b1b1f88a89594d')
    
    res = compile('obj_prop_test.inf', glulx=True)
    res.is_ok(md5='fa5334982d7faf56cc42ea788c8e77cc')
    
    res = compile('obj_prop_test.inf', glulx=True, strict=False)
    res.is_ok(md5='6c6e6bcf3c2715b5f9962dd78e3adee3')
    

def run_statements_test():
    res = compile('switchcasetest.inf')
    res.is_ok(reg='allpass.reg')

    res = compile('switchcasetest.inf', glulx=True)
    res.is_ok(reg='allpass.reg')
    
    res = compile('switchcasetest.inf', define={'TOO_MANY_VALS_1':None})
    res.is_memsetting('MAX_SPEC_STACK')

    res = compile('switchcasetest.inf', define={'TOO_MANY_VALS_2':None})
    res.is_memsetting('MAX_SPEC_STACK')

    res = compile('switchcasetest.inf', glulx=True, define={'TOO_MANY_VALS_1':None})
    res.is_memsetting('MAX_SPEC_STACK')

    res = compile('switchcasetest.inf', glulx=True, define={'TOO_MANY_VALS_2':None})
    res.is_memsetting('MAX_SPEC_STACK')

    res = compile('switchcasetest.inf', define={'DEFAULT_BEFORE_CASE':None})
    res.is_error()

    res = compile('switchcasetest.inf', glulx=True, define={'DEFAULT_BEFORE_CASE':None})
    res.is_error()

    res = compile('switchcasetest.inf', define={'GLOB_VAR_CASE':None})
    res.is_error()

    res = compile('switchcasetest.inf', define={'LOC_VAR_CASE':None})
    res.is_error()

    res = compile('switchcasetest.inf', define={'FUNC_CALL_CASE':None})
    res.is_error()

    res = compile('action_token_err.inf')
    res.is_ok()

    res = compile('action_token_err.inf', define={'NUMBER_ACTION':None})
    res.is_error()

    res = compile('action_token_err.inf', define={'STRING_ACTION':None})
    res.is_error()

    res = compile('action_token_err.inf', define={'UNKNOWN_SYMBOL_ACTION':None})
    res.is_error()

    res = compile('jumpopcodetest.inf')
    res.is_ok(md5='85052b512ed6aba4ab2e5a07ef8116f2')

    res = compile('jumpopcodetest.inf', define={'OPFORM':None})
    res.is_ok(md5='85052b512ed6aba4ab2e5a07ef8116f2')

    res = compile('jumpopcodetest.inf', glulx=True)
    res.is_ok(md5='4286b36138e51806e5c955bc3c66ff94')

    res = compile('jumpopcodetest.inf', glulx=True, define={'OPFORM':None})
    res.is_ok(md5='4286b36138e51806e5c955bc3c66ff94')

    res = compile('jumpbadtest.inf');
    res.is_error()

    res = compile('jumpbadtest.inf', glulx=True);
    res.is_error()


def run_expressions_test():
    res = compile('unaryop_err_test.inf')
    res.is_ok(md5='255de4bef4c60f886d9d86074a259b6b', reg='allpass.reg')

    res = compile('unaryop_err_test.inf', glulx=True)
    res.is_ok(md5='92cf289c108ffb48be16e3aa69be9956', reg='allpass.reg')

    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_0':None})
    res.is_error(errors=1)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_1':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_2':None})
    res.is_error(errors=1)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_3':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_4':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_5':None})
    res.is_error(errors=1)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_6':None})
    res.is_error(errors=1)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_7':None})
    res.is_error(errors=1)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_8':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_9':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_10':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_11':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_12':None})
    res.is_error(errors=3)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_13':None})
    res.is_error(errors=2)
    
    res = compile('unaryop_err_test.inf', define={'BAD_EXPR_14':None})
    res.is_error(errors=2)
    
    res = compile('randomfunc.inf')
    res.is_ok(md5='a1ad53866c6fa2838b3a001e460b9aa5')

    res = compile('randomfunc.inf', glulx=True)
    res.is_ok(md5='de075fc5d37611be364d0772ee082ec5')


def run_debugflag_test():
    res = compile('no_debug_flag_test.inf')
    res.is_ok(warnings=0)

    res = compile('no_debug_flag_test.inf', debug=True, strict=False)
    res.is_error(warnings=1)

    res = compile('no_debug_flag_test.inf', debug=True)
    res.is_error(warnings=1)

    res = compile('no_debug_flag_test.inf', glulx=True)
    res.is_ok(warnings=0)

    # This case succeeds in Glulx because there's no INFIX code in the veneer.
    res = compile('no_debug_flag_test.inf', debug=True, strict=False, glulx=True)
    res.is_ok(warnings=0)

    res = compile('no_debug_flag_test.inf', debug=True, glulx=True)
    res.is_error(warnings=1)


def run_assembytes_test():
    res = compile('assembytes_test.inf')
    res.is_ok(reg='allpass.reg')

    res = compile('assembytes_test.inf', define={ 'BADFUNC_1':None })
    res.is_error()

    res = compile('assembytes_test.inf', define={ 'BADFUNC_2':None })
    res.is_error()

    res = compile('assembytes_test.inf', define={ 'BADFUNC_3':None })
    res.is_error()

    res = compile('assembytes_test.inf', glulx=True)
    res.is_ok(reg='allpass.reg')

    res = compile('assembytes_test.inf', define={ 'BADFUNC_1':None }, glulx=True)
    res.is_error()

    res = compile('assembytes_test.inf', define={ 'BADFUNC_2':None }, glulx=True)
    res.is_error()

    res = compile('assembytes_test.inf', define={ 'BADFUNC_3':None }, glulx=True)
    res.is_error()
    
    
def run_prune_test():
    res = compile('branchprune.inf')
    res.is_ok(md5='ddf87f1d68837b26e90068f5b64dcb12', reg='allpass.reg')

    res = compile('branchprune.inf', glulx=True)
    res.is_ok(md5='acf2fe351129855c4962e3b625cde3f7', reg='allpass.reg')

    res = compile('branchprune.inf', define={ 'BAD_JUMPS':None })
    res.is_error()

    res = compile('branchprune.inf', define={ 'BAD_JUMPS':None }, glulx=True)
    res.is_error()

    res = compile('branchprune.inf', define={ 'BAD_JUMPS':None }, memsettings={'STRIP_UNREACHABLE_LABELS':0 })
    res.is_ok(md5='cd66fef4890d2640c9717a9d5f0afc20', reg='allpass.reg')

    res = compile('branchprune.inf', define={ 'BAD_JUMPS':None }, memsettings={'STRIP_UNREACHABLE_LABELS':0 }, glulx=True)
    res.is_ok(md5='73f2f9dd957cb4d62b0dfaa698681c1e', reg='allpass.reg')

    res = compile('branchprune-fwd.inf')
    res.is_ok(md5='e8330c0fc42a9c459f3e3b9baf284e8e', warnings=1, reg='allpass.reg')

    res = compile('branchprune-fwd.inf', glulx=True)
    res.is_ok(md5='9c48ebcfe754389a50c80c54ee780eb1', warnings=1, reg='allpass.reg')

    res = compile('logicprune.inf')
    res.is_ok(md5='22c4bf399be25593f1bac737312b07dc', warnings=0, reg='allpass.reg')

    res = compile('logicprune.inf', glulx=True)
    res.is_ok(md5='e33841ca3794d30b24265ec70311e53b', warnings=0, reg='allpass.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611')
    res.is_ok(md5='d9b4b1a788ab20554d842c278f590f86', reg='tasksacktest.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_TASKS':None })
    res.is_ok(md5='70443c63b9c049ae1e5760c5e962f1fc', reg='tasksacktest-t.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None })
    res.is_ok(md5='9cde2861ba066676bb5d6ed3efc760db', reg='tasksacktest-s.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None, 'COMPILE_TASKS':None })
    res.is_ok(md5='ab96f1acc336cb54d55424f035c658ab', reg='tasksacktest-st.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', glulx=True)
    res.is_ok(md5='268e2f8851d5aa6bd986c20734ff0932', reg='tasksacktest.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_TASKS':None }, glulx=True)
    res.is_ok(md5='3294f6066418e864a9368ad67ef69455', reg='tasksacktest-t.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None }, glulx=True)
    res.is_ok(md5='d269bcee381dfe11afac8bbf335023e6', reg='tasksacktest-s.reg')

    res = compile('tasksacktest.inf', includedir='i6lib-611', define={ 'COMPILE_SACK':None, 'COMPILE_TASKS':None }, glulx=True)
    res.is_ok(md5='d442688ba330916028fc2ec362458796', reg='tasksacktest-st.reg')


def run_compileopt_test():
    # Can't change DICT_WORD_SIZE in Z-code
    res = compile('optprectest.inf')
    res.is_error()
    
    res = compile('optprectest.inf', glulx=True)
    res.is_ok(md5='7831b6cb6074561cebdc77e53b8af245')
    
    res = compile('optprectest.inf', glulx=True, memsettings={'DICT_WORD_SIZE':12})
    res.is_ok(md5='a29eaf8cad45a33c9753236944f229b1')
    
    res = compile('optprectest.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':19})
    res.is_ok(md5='6e13e68df5b9d02b0d1200bf8df301a0')
    
    res = compile('optprectest.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':19, 'DICT_WORD_SIZE':12})
    res.is_ok(md5='08f73f6698bc2c4329d5c1b1f472b93a')
    
    
def run_defineopt_test():
    res = compile('defineopttest.inf')
    res.is_ok(md5='18316446546580127dfa84c75bec115d')

    res = compile('defineopttest.inf', debug=True)
    res.is_ok(md5='604cd60bc7d5762b3605bbf093a1eb39')

    res = compile('defineopttest.inf', define={ 'DEBUG':None })
    res.is_ok(md5='604cd60bc7d5762b3605bbf093a1eb39')

    res = compile('defineopttest.inf', define={ 'DEBUG':0 })
    res.is_ok(md5='604cd60bc7d5762b3605bbf093a1eb39')

    res = compile('defineopttest.inf', define={ 'FOO':26, 'BAR':-923, 'BAZ':None, 'QUUX':123, 'MUM':-1, 'NERTZ':99999 })
    res.is_ok(md5='6ae1d0138c4da1c7536a7fb8762cabd0')

    # Can't redefine a compiler constant
    res = compile('defineopttest.inf', define={ 'WORDSIZE':3 })
    res.is_error()

    # Symbols are case-insensitive
    res = compile('defineopttest.inf', define={ 'Wordsize':4 })
    res.is_error()

    # Can't redefine a global or other symbol type either
    res = compile('defineopttest.inf', define={ 'sw__var':None })
    res.is_error()

    res = compile('defineopttest.inf', define={ 'name':1 })
    res.is_error()

    # Can't define the same constant twice (symbols are case-insensitive!)
    res = compile('defineopttest.inf', define={ 'XFOO':1, 'xfoo':2 })
    res.is_error()

    # Redefining a constant to the same value is ok
    res = compile('defineopttest.inf', define={ 'WORDSIZE':2 })
    res.is_ok(md5='18316446546580127dfa84c75bec115d')

    res = compile('defineopttest.inf', define={ 'XFOO':3, 'xfoo':3 })
    res.is_ok(md5='18316446546580127dfa84c75bec115d')

    res = compile('defineopttest.inf', glulx=True)
    res.is_ok(md5='333fe8a75515113435491c94d3d6e57f')

    res = compile('defineopttest.inf', glulx=True, debug=True)
    res.is_ok(md5='e2edd7ab2c5a51cbcc998ea76a2bfcb1')

    res = compile('defineopttest.inf', glulx=True, define={ 'DEBUG':None })
    res.is_ok(md5='e2edd7ab2c5a51cbcc998ea76a2bfcb1')

    res = compile('defineopttest.inf', glulx=True, define={ 'DEBUG':0 })
    res.is_ok(md5='e2edd7ab2c5a51cbcc998ea76a2bfcb1')

    res = compile('defineopttest.inf', glulx=True, define={ 'Wordsize':4 })
    res.is_ok(md5='333fe8a75515113435491c94d3d6e57f')


def run_fwconst_test():
    res = compile('fwconst_release_test.inf')
    res.is_error()

    res = compile('fwconst_release_test.inf', define={ 'FORWARD_CONSTANT':7 })
    res.is_ok()

    res = compile('fwconst_release_test.inf', glulx=True)
    res.is_error()

    res = compile('fwconst_release_test.inf', define={ 'FORWARD_CONSTANT':7 }, glulx=True)
    res.is_ok()

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z5')
    res.is_error()

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z3', define={ 'FORWARD_CONSTANT':3 })
    res.is_ok(md5='e8b044eaef2b489db9ab0a1cc0f2bc5f')

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z5', define={ 'FORWARD_CONSTANT':5 })
    res.is_ok(md5='90866a483312a4359bc00db776e6eed4')

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z8', define={ 'FORWARD_CONSTANT':8 })
    res.is_ok(md5='fa7fc9bbe032d27355b0fcf4fb4f2c53')

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z9', define={ 'FORWARD_CONSTANT':9 })
    res.is_error()

    res = compile('fwconst_dictionary_test.inf')
    res.is_error()

    res = compile('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1 })
    res.is_error()

    res = compile('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_B':2 })
    res.is_error()

    res = compile('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1, 'FORWARD_CONSTANT_B':2 })
    res.is_ok()

    res = compile('fwconst_dictionary_test.inf', glulx=True)
    res.is_error()

    res = compile('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1 }, glulx=True)
    res.is_error()

    res = compile('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_B':2 }, glulx=True)
    res.is_error()

    res = compile('fwconst_dictionary_test.inf', define={ 'FORWARD_CONSTANT_A':1, 'FORWARD_CONSTANT_B':2 }, glulx=True)
    res.is_ok()

    res = compile('fwconst_iftrue_test.inf')
    res.is_error()

    res = compile('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':1 })
    res.is_error()

    res = compile('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_B':1 })
    res.is_error()

    res = compile('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':1, 'FORWARD_CONSTANT_B':1 })
    res.is_ok()

    res = compile('fwconst_iftrue_test.inf', glulx=True)
    res.is_error()

    res = compile('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':0 }, glulx=True)
    res.is_error()

    res = compile('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_B':0 }, glulx=True)
    res.is_error()

    res = compile('fwconst_iftrue_test.inf', define={ 'FORWARD_CONSTANT_A':0, 'FORWARD_CONSTANT_B':0 }, glulx=True)
    res.is_ok()


def run_debugfile_test():
    res = compile('Advent.inf', includedir='i6lib-611', debugfile=True)
    res.is_ok(md5='253056d3e169c9c3d871525918260eb3', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', debugfile=True, glulx=True)
    res.is_ok(md5='b2bb42f3ff9b001cb11238bcbd3ae0f5', warnings=0)


def run_warnings_test():
    res = compile('typewarningtest.inf')
    res.is_ok(warnings=83)
    
    res = compile('typewarningtest.inf', glulx=True)
    res.is_ok(warnings=85)
    
    res = compile('callwarningtest.inf')
    res.is_ok(warnings=61)
    
    res = compile('callwarningtest.inf', glulx=True)
    res.is_ok(warnings=62)
    
    res = compile('or_warnings_test.inf')
    res.is_ok(warnings=11)
    
    res = compile('or_warnings_test.inf', glulx=True)
    res.is_ok(warnings=11)
    
    res = compile('or_condition_test.inf')
    res.is_ok(md5='04d4c51ead347b626bf34bfdb80ac81c', warnings=4, reg='allpass.reg')

    res = compile('or_condition_test.inf', glulx=True)
    res.is_ok(md5='34cbc765cb174293b06b97d3bdbc8258', warnings=4, reg='allpass.reg')


def run_trace_test():
    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'ACTIONS':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'ASM':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'ASM':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'ASM':3 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'ASM':4 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'BPATCH':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'BPATCH':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'DICT':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'DICT':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'EXPR':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'EXPR':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'EXPR':3 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'FILES':1 })
    res.is_ok()

    res = compile('abbrevtest.inf', makeabbrevs=True, trace={ 'FINDABBREVS':1 })
    res.is_ok()
    
    res = compile('abbrevtest.inf', makeabbrevs=True, trace={ 'FINDABBREVS':2 })
    res.is_ok()
    
    res = compile('abbrevtest.inf', economy=True, trace={ 'FREQ':1 })
    res.is_ok()
    
    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'MAP':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'MAP':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'MEM':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'OBJECTS':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'PROPS':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'STATS':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'SYMBOLS':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'SYMDEF':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'SYMBOLS':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'TOKENS':1 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'TOKENS':2 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'TOKENS':3 })
    res.is_ok()

    res = compile('Advent.inf', includedir='i6lib-611', trace={ 'VERBS':1 })
    res.is_ok()


def run_abbreviations_test():
    res = compile('max_abbrev_len_test.inf')
    res.is_ok(warnings=0)
    
    res = compile('short_abbrevs_test.inf', economy=True)
    res.is_ok(warnings=4)

    res = compile('symbolic_abbrev_test.inf')
    res.is_ok(reg='allpass.reg')

    res = compile('symbolic_abbrev_test.inf', glulx=True)
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':102}, glulx=True)
    res.is_ok(reg='allpass.reg')

    res = compile('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':0})
    res.is_error()

    res = compile('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':0}, glulx=True)
    res.is_error()

    res = compile('symbolic_abbrev_test.inf', define={'BADSYNTAX':None})
    res.is_error(errors=8)

    res = compile('symbolic_abbrev_test.inf', memsettings={'MAX_DYNAMIC_STRINGS':102}, define={'BADSYNTAX':None}, glulx=True)
    res.is_error(errors=8)

    
def run_make_abbreviations_test():
    res = compile('abbrevtest.inf', makeabbrevs=True, economy=True)
    res.is_ok(abbreviations=['. ', ', ', '**]', "='@", ' the', 'tried to print (', 'string', 'objec', ' on something n', ' here', ' tha', "31'.^", 'ing', ' to ', 'tribute', '~ o', 'lass', 'ate', 'ther', 'which', 'for', ': 0', "16'", 'ave', 'loop', 'can', 'mber', 'tion', 'is n', 'cre', 'use', 'ed ', 'at ', 'or ', 'ot ', 'has', "00'", "01'", '-- ', 'est', 'er ', 'hall ', 'is ', 'in ', 'we ', 'ead', 'of ', 'out', 'rem', ' a ', 'not', 'nse', 'ove', ' de', ' to', ' it', ' wh', ' us', 'se ', 'de '], warnings=11)

    res = compile('long_abbrevtest.inf', makeabbrevs=True, economy=True)
    res.is_ok(abbreviations=['. ', ', ', 'This ', 'is a long string the likes of which may not have been seen in the text -- '])

    res = compile('longer_abbrevtest.inf', makeabbrevs=True, economy=True)
    res.is_ok(abbreviations=['. ', ', ', 'This ', 'is a long string the likes of which may not have been seen in the text on a Tuesday in April with the sun shining and elephants fluttering by; oh have you considered the song of the elephants; there is nothing like it -- '])

    res = compile('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True)
    res.is_ok(abbreviations=['. ', ', ', 'You ', "'t ", 'ing ', '**]', 'The', 'That', 'you can', 'someth', '_to)', 'closed', 're ', 'bject', 'already ', 'But ', 's no', 'which ', ' to ', 'ing', 'can', "You'", 'ome', 'the', 'your', 'Command', 't of', 'achieve', 'Language', 'scrip', 'have', 'tion', 'ou aren', 'seem', 'nd ', 'you', 'at ', 'noth', 'see ', 'ose ', 'ed.', 'of ', 'ed ', 'ch ', 'ect', 'not ', 'Not', 'in ', 'read', 'would ', 'on ', 'You', 'ere.', 'int', 'provid', 'est', 'empt', 'lock', '~ or ', 'ight', 'is ', 've ', 'me ', 'first'])

    res = compile('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':2})
    res.is_ok(abbreviations=['. ', ', '])

    res = compile('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':10})
    res.is_ok(abbreviations=['. ', ', ', 'You ', "'t ", 'ing ', '**]', ' th', 'ou can', 'The', 'That'])

    res = compile('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':20})
    res.is_ok(abbreviations=['. ', ', ', 'You ', '\'t ', 'ing ', '**]', 'The', 'That', 'you can', 'someth', ' th', ' you', ' on', 'ing', 'can', ' not', ' ha', ' of', ' seem', 'You\''])

    res = compile('include_english.inf', includedir='i6lib-611', makeabbrevs=True, economy=True, memsettings={'MAX_ABBREVS':96})
    res.is_ok(abbreviations=['. ', ', ', 'You ', '\'t ', 'ing ', '**]', 'The', 'That', 'you can', 'someth', '_to)', 're ', 'closed', 'bject', 'But ', 's no', 'already ', 'which ', 'Command', 'script', ' to ', 'ing', 'can', 'You\'', 'ome', 'tion', 'the', 'your', 't of', 'achieve', 'Language', 'have', 'ou aren', 'Those', 'ou wan', 'this', 'provid', 'would', 'ter', 'unexpected', 'lock', 'nd ', 'you', 'at ', 'noth', 'of ', 'ed.', 'ed ', 'se ', 'ch ', 'is ', 'Not', 'not ', 'in ', 'seem', 'read', 'on ', 'You', 'ere.', 'est', 'er ', '~ or ', 'ight', 'first', 'int', 've ', 'see ', 'as ', 'ly ', 'ide ', 'ect', 'put ', 'en ', 'an ', 'lass ', 'ns ', 'record', 'It ', 'ent', '\'s ', 'off ', 'get ', 'nce ', 'I d', 'ort', 'le.', 'be ', 'wit', 'le ', 'ious ', 'gam', 'n\'t', 'off.', 'on.', ' th', ' on'])

    
def run_max_ifdef_stack():
    # Fixed limit; no memory setting to change.
    
    res = compile('max_ifdef_stack_32.inf')
    res.is_ok()

    res = compile('max_ifdef_stack_33.inf')
    res.is_memsetting('MAX_IFDEF_STACK')

def run_max_switch_case_values():
    # Fixed limit

    res = compile('max_switch_case_values.inf')
    res.is_ok()

    res = compile('max_switch_case_values.inf', define={ 'SWITCH_ERROR':0 })
    res.is_memsetting('MAX_SPEC_STACK')

    
def run_max_inclusion_depth():
    res = compile('max_inclusion_depth_test.inf', includedir='src/include')
    res.is_ok()
    
    res = compile('max_inclusion_depth_test.inf', includedir='src/include', glulx=True)
    res.is_ok()


def run_max_source_files():
    res = compile('max_source_files_test.inf', includedir='src/include')
    res.is_ok()
    
    res = compile('max_origsource_direct_test.inf')
    res.is_ok()
    

def run_max_unicode_chars_test():
    res = compile('max_unicode_chars_test.inf', glulx=True)
    res.is_ok()

    
def run_max_symbols():
    res = compile('max_symbols_test.inf')
    res.is_ok()
    
    res = compile('max_symbols_test.inf', glulx=True)
    res.is_ok()


def run_symbols_chunk_size():
    res = compile('max_symbols_test.inf')
    res.is_ok()
    
    res = compile('max_symbols_test.inf', glulx=True)
    res.is_ok()


def run_max_objects():
    res = compile('max_objects_test.inf')
    res.is_ok()

    res = compile('max_objects_test.inf', glulx=True)
    res.is_ok()

    res = compile('max_duplicate_objects_test.inf', glulx=True)
    res.is_ok()


def run_max_classes():
    res = compile('max_classes_test.inf')
    res.is_ok()

    res = compile('max_classes_test.inf', glulx=True)
    res.is_ok()


def run_max_arrays():
    res = compile('max_arrays_test.inf')
    res.is_ok()

    res = compile('max_arrays_test.inf', glulx=True)
    res.is_ok()

    res = compile('max_arrays_test_2.inf')
    res.is_ok()

    res = compile('max_arrays_test_2.inf', glulx=True)
    res.is_ok()

    res = compile('max_arrays_test_3.inf')
    res.is_ok()

    res = compile('max_arrays_test_3.inf', glulx=True)
    res.is_ok()


def run_max_attr_bytes():
    res = compile('max_attributes.inf')
    res.is_memsetting('MAX_ATTRIBUTES')
    
    res = compile('max_attributes.inf', glulx=True)
    res.is_memsetting('MAX_ATTRIBUTES')
    
    res = compile('max_attributes.inf', glulx=True, memsettings={'NUM_ATTR_BYTES':11})
    res.is_ok()
    

def run_max_prop_table_size():
    res = compile('max_prop_table_size_test.inf')
    res.is_ok()

    res = compile('max_prop_table_size_test.inf', glulx=True)
    res.is_ok()

    # Glulx uses this setting for individual properties too

    res = compile('max_indiv_prop_table_size_test.inf', glulx=True)
    res.is_ok()

    # A single large object can run into this setting too.
    
    res = compile('max_obj_prop_table_size_test.inf', glulx=True)
    res.is_ok()

    # So can a Z-code object's shortname.

    res = compile('large_object_short_name_test.inf')
    res.is_ok()

    res = compile('large_object_short_name_test_2.inf')
    res.is_memsetting('MAX_SHORT_NAME_LENGTH')


def run_max_common_prop_count():
    res = compile('max_common_props_test.inf')
    res.is_memsetting('MAX_COMMON_PROPS')

    res = compile('max_common_props_test.inf', zversion=3)
    res.is_memsetting('MAX_COMMON_PROPS')

    res = compile('max_common_props_test.inf', glulx=True)
    res.is_ok()

    res = compile('max_common_props_test_280.inf', glulx=True)
    res.is_memsetting('MAX_COMMON_PROPS')

    res = compile('max_common_props_test_280.inf', memsettings={'INDIV_PROP_START':283}, glulx=True)
    res.is_memsetting('MAX_COMMON_PROPS')

    res = compile('max_common_props_test_280.inf', memsettings={'INDIV_PROP_START':284}, glulx=True)
    res.is_ok()

    res = compile('common_props_plus_test.inf')
    res.is_ok()

    res = compile('common_props_plus_test.inf', define={ 'TOOMANY':0 })
    res.is_memsetting('MAX_COMMON_PROPS')


def run_max_common_prop_size():
    res = compile('max_prop_size_test.inf', define={ 'MAX_COMMON_PROP':0 })
    res.is_ok()
    
    res = compile('max_prop_size_test.inf', define={ 'TOOBIG_COMMON_PROP':0 })
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('max_prop_size_test.inf', define={ 'MAX_ADDITIVE_PROP':0 })
    res.is_ok()
    
    res = compile('max_prop_size_test.inf', define={ 'TOOBIG_ADDITIVE_PROP':0 })
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('max_prop_size_test.inf', zversion=3, define={ 'MAX_COMMON_PROP_V3':0 })
    res.is_ok()
    
    res = compile('max_prop_size_test.inf', zversion=3, define={ 'TOOBIG_COMMON_PROP_V3':0 })
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('max_prop_size_test.inf', zversion=3, define={ 'MAX_ADDITIVE_PROP_V3':0 })
    res.is_ok()
    
    res = compile('max_prop_size_test.inf', zversion=3, define={ 'TOOBIG_ADDITIVE_PROP_V3':0 })
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('max_prop_size_test.inf', define={ 'MAX_CLASSES':0 })
    res.is_ok()
    
    res = compile('max_prop_size_test.inf', define={ 'TOOBIG_CLASSES':0 })
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('max_prop_size_test.inf', zversion=3, define={ 'MAX_CLASSES_V3':0 })
    res.is_ok()
    
    res = compile('max_prop_size_test.inf', zversion=3, define={ 'TOOBIG_CLASSES_V3':0 })
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    
def run_max_indiv_prop_table_size():
    res = compile('max_indiv_prop_table_size_test.inf')
    res.is_ok()

    # Glulx does not use this setting, so no Glulx tests.

    
def run_max_obj_prop_table_size():
    res = compile('max_obj_prop_table_size_test.inf', glulx=True)
    res.is_ok()


def run_max_obj_prop_count():
    res = compile('max_obj_prop_count_test.inf', glulx=True)
    res.is_ok()

    res = compile('property_too_long.inf')
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('property_too_long.inf', glulx=True)
    res.is_ok()
    
    res = compile('property_too_long_inherit.inf')
    res.is_memsetting('MAX_PROP_LENGTH_ZCODE')
    
    res = compile('property_too_long_inherit.inf', glulx=True)
    res.is_ok()
    

def run_max_global_variables():
    # In Z-code, at most 233 globals are available, and you can't raise the
    # limit.
    res = compile('max_global_variables_test.inf')
    res.is_ok()
    
    res = compile('max_global_variables_test_2.inf')
    res.is_memsetting('MAX_GLOBAL_VARIABLES')
    
    res = compile('max_global_variables_test_2.inf', glulx=True)
    res.is_ok()


def run_max_local_variables():
    # In Z-code, at most 15 locals are available, and you can't raise the
    # limit. In Glulx, at most 118.
    
    res = compile('max_local_variables_test_15.inf')
    res.is_ok()
    
    res = compile('max_local_variables_test_16.inf')
    res.is_memsetting('MAX_LOCAL_VARIABLES')

    res = compile('max_local_variables_test_16.inf', glulx=True)
    res.is_ok()

    res = compile('max_local_variables_test_31.inf', glulx=True)
    res.is_ok()

    res = compile('max_local_variables_test_32.inf', glulx=True)
    res.is_ok()

    res = compile('max_local_variables_test_118.inf', glulx=True)
    res.is_ok()

    res = compile('max_local_variables_test_119.inf', glulx=True)
    res.is_memsetting('MAX_LOCAL_VARIABLES')

    
def run_max_static_data():
    res = compile('max_static_data_test.inf')
    res.is_ok()

    res = compile('max_static_data_test.inf', glulx=True)
    res.is_ok()

    res = compile('max_static_data_test_2.inf')
    res.is_ok()

    res = compile('max_static_data_test_2.inf', glulx=True)
    res.is_ok()

    res = compile('max_static_data_test_3.inf')
    res.is_ok()

    res = compile('max_static_data_test_3.inf', glulx=True)
    res.is_ok()


def run_max_num_static_strings():
    # Glulx only

    res = compile('static_text_test.inf', glulx=True)
    res.is_ok()

    
def run_max_qtext_size():
    res = compile('max_static_strings_test.inf')
    res.is_ok()

    res = compile('max_static_strings_test.inf', glulx=True)
    res.is_ok()

    
def run_max_static_strings():
    # The compiler ensures that MAX_STATIC_STRINGS is (at least) twice
    # MAX_QTEXT_SIZE.
    
    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001})
    res.is_ok()

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001}, glulx=True)
    res.is_ok()


def run_max_low_strings():
    # Only meaningful for Z-code.
    
    res = compile('max_low_strings_test.inf')
    res.is_ok()

    
def run_max_dynamic_strings():
    res = compile('max_dynamic_strings_test_at15.inf', memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at31.inf', memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at32.inf', memsettings={})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at15.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at31.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at32.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at63.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at64.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_str31.inf', memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str32.inf', memsettings={})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_str31.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str32.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str63.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str64.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':64})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at32.inf', memsettings={'MAX_DYNAMIC_STRINGS':33})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at95.inf', memsettings={'MAX_DYNAMIC_STRINGS':95})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at95.inf', memsettings={'MAX_DYNAMIC_STRINGS':96})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str31.inf', memsettings={'MAX_ABBREVS':65})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at31.inf', memsettings={'MAX_ABBREVS':65})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at95.inf', memsettings={'MAX_ABBREVS':1})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at95.inf', memsettings={'MAX_ABBREVS':0})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str64.inf', memsettings={'MAX_ABBREVS':31})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str32.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':32})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at32.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':32})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_str64.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':65})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at99.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':99})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_at99.inf', glulx=True, memsettings={})
    res.is_ok()

    
def run_max_inline_string():
    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':64})
    res.is_ok(md5='e3a3596dc96cb0831ba6479a454c15c9', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':800})
    res.is_ok(md5='a1d869ded019775884d7e5a6351356b2', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'ZCODE_MAX_INLINE_STRING':10000})
    res.is_ok(md5='a1d869ded019775884d7e5a6351356b2', warnings=0, reg='Advent-z.reg')

    res = compile('max_inline_string_test.inf')
    res.is_ok(warnings=0)

    res = compile('max_inline_string_test.inf', memsettings={'ZCODE_MAX_INLINE_STRING':999})
    res.is_ok(warnings=0)

    res = compile('max_inline_string_test.inf', memsettings={'ZCODE_MAX_INLINE_STRING':1000})
    res.is_error()

    
    
def run_max_abbrevs():
    res = compile('abbrevtest.inf')
    res.is_ok(md5='870285d50c252cde8bbd0ef2bc977a56')
    
    res = compile('abbrevtest.inf', glulx=True)
    res.is_ok(md5='fa2130036715d5ec0f6b7e53a1f74e2c')
    
    res = compile('abbrevtest.inf', economy=True)
    res.is_ok(md5='99be12467aea61fb46ee46143d903906')
    
    res = compile('abbrevtest.inf', glulx=True, economy=True)
    res.is_ok(md5='774d0dd65eabbbc84a41aa1324f567c3')
    
    res = compile('Advent-abbrev.inf', includedir='i6lib-611')
    res.is_ok(md5='253056d3e169c9c3d871525918260eb3')
    
    res = compile('Advent-abbrev.inf', includedir='i6lib-611', glulx=True)
    res.is_ok(md5='b2bb42f3ff9b001cb11238bcbd3ae0f5')
    
    res = compile('Advent-abbrev.inf', includedir='i6lib-611', economy=True)
    res.is_ok(md5='e64e6549b6d6387f775f6d92be482cf6')
    
    res = compile('Advent-abbrev.inf', includedir='i6lib-611', glulx=True, economy=True)
    res.is_ok(md5='9d24eb5f77a07a03c83993ae3c503801')
    
    res = compile('i7-min-6G60-abbrev.inf', zversion=8, economy=True)
    res.is_ok(md5='ac0ff916044088c303bb441a92378eb7', reg='i7-min-6G60.reg')
    
    res = compile('max_abbrevs_test_64.inf', economy=True, memsettings={})
    res.is_ok()

    res = compile('max_abbrevs_test_64.inf', economy=True, memsettings={'MAX_ABBREVS':63})
    res.is_memsetting('MAX_ABBREVS')

    res = compile('max_abbrevs_test_32.inf', economy=True, memsettings={'MAX_ABBREVS':32})
    res.is_ok()

    res = compile('max_abbrevs_test_32.inf', economy=True, memsettings={'MAX_ABBREVS':31})
    res.is_memsetting('MAX_ABBREVS')

    res = compile('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_ABBREVS':96})
    res.is_ok()

    res = compile('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_ABBREVS':95})
    res.is_memsetting('MAX_ABBREVS')

    res = compile('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_DYNAMIC_STRINGS':0})
    res.is_ok()

    res = compile('max_abbrevs_test_96.inf', economy=True, memsettings={'MAX_DYNAMIC_STRINGS':1})
    res.is_memsetting('MAX_ABBREVS')

    res = compile('max_abbrevs_test_100.inf', economy=True, memsettings={'MAX_ABBREVS':96})
    res.is_memsetting('MAX_ABBREVS')

    res = compile('max_abbrevs_test_64.inf', economy=True, glulx=True)
    res.is_ok()

    res = compile('max_abbrevs_test_32.inf', economy=True, glulx=True)
    res.is_ok()

    res = compile('max_abbrevs_test_96.inf', economy=True, glulx=True)
    res.is_ok()

    res = compile('max_abbrevs_test_100.inf', economy=True, glulx=True)
    res.is_ok()


def run_max_verb_word_size():
    # Fixed limit; no memory setting to change.
    
    res = compile('max_verb_word_size.inf')
    res.is_ok()

    res = compile('max_verb_word_size_2.inf')
    res.is_ok()
    
    res = compile('max_verb_word_size.inf', glulx=True)
    res.is_ok()

    res = compile('max_verb_word_size_2.inf', glulx=True)
    res.is_ok()


def run_max_lines_per_verb():
    res = compile('max_lines_per_verb_32.inf')
    res.is_ok()

    res = compile('max_lines_per_verb_33.inf')
    res.is_ok()

    res = compile('max_lines_per_verb_40.inf')
    res.is_ok()

    res = compile('max_lines_per_verb_40.inf', glulx=True)
    res.is_ok()

    res = compile('max_lines_per_verb_extfirst.inf')
    res.is_ok()

    res = compile('max_lines_per_verb_extfirst.inf', glulx=True)
    res.is_ok()

    res = compile('max_lines_per_verb_extlast.inf')
    res.is_ok()

    res = compile('max_lines_per_verb_extlast.inf', glulx=True)
    res.is_ok()

    
def run_max_linespace():
    res = compile('max_linespace_test.inf')
    res.is_ok()

    
def run_max_verb_synonyms():
    res = compile('max_verb_synonyms_32.inf')
    res.is_ok()

    res = compile('max_verb_synonyms_33.inf')
    res.is_ok()
    
    
def run_max_verbs():
    res = compile('max_verbs.inf')
    res.is_ok()
    
    res = compile('max_verbs.inf', glulx=True)
    res.is_ok()
    
    res = compile('max_verbs_2.inf')
    res.is_memsetting('MAX_VERBS_ZCODE')
    
    res = compile('max_verbs_2.inf', glulx=True)
    res.is_ok()
    
    res = compile('max_verbs_3.inf')
    res.is_memsetting('MAX_VERBS_ZCODE')
    
    res = compile('max_verbs_3.inf', glulx=True)
    res.is_ok()
    
    
def run_unused_verbs():
    res = compile('unused_verbs.inf')
    res.is_ok(warnings=0)
    
    res = compile('unused_verbs.inf', define={ 'ONLYFOO':0 })
    res.is_ok(warnings=0)
    
    res = compile('unused_verbs.inf', define={ 'ONLYFOOX':0 })
    res.is_ok(warnings=0)
    
    res = compile('unused_verbs.inf', define={ 'ONLYFOO':0, 'ONLYFOOX':0 })
    res.is_ok(warnings=1)
    
    res = compile('unused_verbs.inf', glulx=True)
    res.is_ok(warnings=0)
    
    res = compile('unused_verbs.inf', define={ 'ONLYFOO':0, 'ONLYFOOX':0 }, glulx=True)
    res.is_ok(warnings=1)
    
    res = compile('unused_verbs.inf', define={ 'ONLYFOO':0, 'ONLYZOGA':0 })
    res.is_ok(warnings=0)
    
    res = compile('unused_verbs.inf', define={ 'ONLYZOG':0, 'ONLYZOGA':0 })
    res.is_ok(warnings=1)
    
    res = compile('unused_verbs_lib.inf', includedir='i6lib-611')
    res.is_ok(md5='f94c7a7bc1f91993e9af839d23406375', warnings=2)
    
    res = compile('unused_verbs_lib.inf', includedir='i6lib-611', glulx=True)
    res.is_ok(md5='05be572921b1a2d3ae9ee71314ebaf97', warnings=2)
    
    
def run_max_actions():
    res = compile('max_actions.inf')
    res.is_ok()

    res = compile('max_actions.inf', glulx=True)
    res.is_ok()

    # Can't handle 400 actions in grammar version 1
    res = compile('max_actions.inf', define={ 'MAKE_400':0 })
    res.is_error()

    res = compile('max_actions.inf', define={ 'MAKE_400':0 }, memsettings={ 'GRAMMAR_VERSION':2 })
    res.is_ok()

    res = compile('max_actions.inf', glulx=True, define={ 'MAKE_400':0 })
    res.is_ok()

    res = compile('max_actions.inf', glulx=True)
    res.is_ok()

    res = compile('max_grammar_routines_test.inf')
    res.is_ok()

    # Glulx uses Grammar__Version 2, so the grammar_token_routine table is not used.
    res = compile('max_grammar_routines_test.inf', glulx=True)
    res.is_ok()

    
def run_max_adjectives():
    res = compile('max_adjectives.inf')
    res.is_ok()

    # Glulx uses Grammar__Version 2, so adjectives are not used.
    res = compile('max_adjectives.inf', glulx=True)
    res.is_ok()

    res = compile('max_adjectives_2.inf')
    res.is_ok()

    res = compile('max_adjectives_2.inf', glulx=True)
    res.is_ok()

    res = compile('max_adjectives_256.inf')
    res.is_memsetting('MAX_PREPOSITIONS_GV1')

    res = compile('max_adjectives_256.inf', define={ 'USE_GV2':0 })
    res.is_ok()

    res = compile('max_adjectives_256.inf', glulx=True)
    res.is_ok()

    
def run_max_expression_nodes():
    res = compile('max_expression_nodes_test.inf')
    res.is_ok()

    res = compile('max_expression_nodes_test.inf', glulx=True)
    res.is_ok()

    res = compile('max_expression_nodes_test_2.inf')
    res.is_ok()

    res = compile('max_expression_nodes_test_2.inf', glulx=True)
    res.is_ok()

    res = compile('max_expression_nodes_test_3.inf')
    res.is_ok()

    res = compile('max_expression_nodes_test_3.inf', glulx=True)
    res.is_ok()


def run_max_labels():
    res = compile('max_labels_test.inf')
    res.is_ok()
    
    res = compile('max_labels_test.inf', glulx=True)
    res.is_ok()


def run_max_zcode_size():
    res = compile('large_opcode_text_test.inf', memsettings={'MAX_QTEXT_SIZE':8001})
    res.is_ok()

    res = compile('max_zcode_size_test.inf')
    res.is_ok()

    res = compile('max_zcode_size_test.inf', glulx=True)
    res.is_ok()

    res = compile('zcode_v3_overflow.inf', zversion=3)
    res.is_error()

    res = compile('zcode_v3_overflow.inf')
    res.is_ok()

    res = compile('zcode_v3_overflow.inf', glulx=True)
    res.is_ok()


def run_omit_unused_routines():
    res = compile('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1})
    res.is_ok()
    res.is_ok(md5='ff71d68c123d6b9a14c2b517ffee6092', reg='i7-min-6G60.reg')

    res = compile('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True)
    res.is_ok()
    res.is_ok(md5='b13da005eaa80081fed605a9a4bd5b38', reg='i7-min-6G60.reg')

    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_UNUSED_ROUTINES':1})
    res.is_ok(md5='14a490c75ad8817fb6816648f1078475', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True)
    res.is_ok(md5='413afb10dc9d7f0a6f177c6b645262cd', warnings=0, reg='Advent-g.reg')

    res = compile('strip_func_test.inf', memsettings={'OMIT_UNUSED_ROUTINES':1})
    res.is_ok()
    res.is_ok(md5='07bd8dcf2c8f3a8e544a53584e417ad2')

    res = compile('strip_func_test.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True)
    res.is_ok()
    res.is_ok(md5='5ebeba63f77407fc175f00055f565933')


def run_omit_symbol_table():
    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_SYMBOL_TABLE':1})
    res.is_ok(md5='8b41c12a48a958390f5df982caf61925', warnings=0, reg='Advent-z.reg')

    res = compile('Advent.inf', includedir='i6lib-611', memsettings={'OMIT_SYMBOL_TABLE':1}, glulx=True)
    res.is_ok(md5='6b4d9ac807dda0711273a68088656a27', warnings=0, reg='Advent-g.reg')

    res = compile('library_of_horror-36.inf', includedir='punylib-36', memsettings={'OMIT_SYMBOL_TABLE':1}, zversion=3)
    res.is_ok(md5='056bbf78da27da63d3458ec48ea238c0', reg='library_of_horror.reg')
    
    res = compile('omit-symbol-table-test.inf', memsettings={'OMIT_SYMBOL_TABLE':1})
    res.is_ok(md5='1807eb07c43622227080f765948a59f0', warnings=0)

    res = compile('omit-symbol-table-test.inf', memsettings={'OMIT_SYMBOL_TABLE':1}, glulx=True)
    res.is_ok(md5='c674e8217a693124dfd0404fbe9b36dc', warnings=0)

    
def run_file_end_padding():
    res = compile('minimal_test.inf', memsettings={'ZCODE_FILE_END_PADDING':0})
    res.is_ok(md5='1847d28cc183ec23c50bd5bca52a1b21')

    res = compile('i7-min-6G60.inf', memsettings={'ZCODE_FILE_END_PADDING':0})
    res.is_ok(md5='7147492b1d2c624e78dea4e696f61c99', reg='i7-min-6G60.reg')

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8)
    res.is_ok(md5='91ceadaf4e9077a111941a27f342a4dd', reg='Advent-z.reg')

    res = compile('library_of_horror-16.inf', includedir='punylib-16', zversion=3, memsettings={'ZCODE_FILE_END_PADDING':0})
    res.is_ok(md5='80077189b1e682930e661cbe09e46d0a')

    res = compile('library_of_horror-36.inf', includedir='punylib-36', memsettings={'ZCODE_FILE_END_PADDING':0}, zversion=3)
    res.is_ok(md5='7b512bfccbb332c6b90be25c2a786b8a', reg='library_of_horror.reg')
    


test_catalog = [
    ('CHECKSUM', run_checksum_test),
    ('DICT', run_dict_test),
    ('GRAMMAR', run_grammar_test),
    ('LEXER', run_lexer_test),
    ('VENEER', run_veneer_test),
    ('DIRECTIVES', run_directives_test),
    ('STATEMENTS', run_statements_test),
    ('EXPRESSIONS', run_expressions_test),
    ('ASSEMBYTES', run_assembytes_test),
    ('PRUNE', run_prune_test),
    ('DEBUGFLAG', run_debugflag_test),
    ('COMPILEOPT', run_compileopt_test),
    ('DEFINEOPT', run_defineopt_test),
    ('FWCONST', run_fwconst_test),
    ('DEBUGFILE', run_debugfile_test),
    ('WARNINGS', run_warnings_test),
    ('TRACE', run_trace_test),
    ('ABBREVIATIONS', run_abbreviations_test),
    ('MAKE_ABBREVIATIONS', run_make_abbreviations_test),
    ('MAX_IFDEF_STACK', run_max_ifdef_stack),
    ('MAX_SWITCH_CASE_VALUES', run_max_switch_case_values),
    ('MAX_INCLUSION_DEPTH', run_max_inclusion_depth),
    ('MAX_SOURCE_FILES', run_max_source_files),
    ('MAX_UNICODE_CHARS', run_max_unicode_chars_test),
    ('MAX_SYMBOLS', run_max_symbols),
    ('SYMBOLS_CHUNK_SIZE', run_symbols_chunk_size),
    ('MAX_OBJECTS', run_max_objects),
    ('MAX_CLASSES', run_max_classes),
    ('MAX_ARRAYS', run_max_arrays),
    ('MAX_ATTR_BYTES', run_max_attr_bytes),
    ('MAX_PROP_TABLE_SIZE', run_max_prop_table_size),
    ('MAX_COMMON_PROP_COUNT', run_max_common_prop_count),
    ('MAX_COMMON_PROP_SIZE', run_max_common_prop_size),
    ('MAX_INDIV_PROP_TABLE_SIZE', run_max_indiv_prop_table_size),
    ('MAX_OBJ_PROP_TABLE_SIZE', run_max_obj_prop_table_size),
    ('MAX_OBJ_PROP_COUNT', run_max_obj_prop_count),
    ('MAX_GLOBAL_VARIABLES', run_max_global_variables),
    ('MAX_LOCAL_VARIABLES', run_max_local_variables),
    ('MAX_STATIC_DATA', run_max_static_data),
    ('MAX_NUM_STATIC_STRINGS', run_max_num_static_strings),
    ('MAX_QTEXT_SIZE', run_max_qtext_size),
    ('MAX_STATIC_STRINGS', run_max_static_strings),
    ('MAX_LOW_STRINGS', run_max_low_strings),
    ('MAX_DYNAMIC_STRINGS', run_max_dynamic_strings),
    ('MAX_INLINE_STRING', run_max_inline_string),
    ('MAX_ABBREVS', run_max_abbrevs),
    ('MAX_VERBS', run_max_verbs),
    ('UNUSED_VERBS', run_unused_verbs),
    ('MAX_VERB_WORD_SIZE', run_max_verb_word_size),
    ('MAX_VERB_SYNONYMS', run_max_verb_synonyms),
    ('MAX_LINES_PER_VERB', run_max_lines_per_verb),
    ('MAX_LINESPACE', run_max_linespace),
    ('MAX_ACTIONS', run_max_actions),
    ('MAX_ADJECTIVES', run_max_adjectives),
    ('MAX_EXPRESSION_NODES', run_max_expression_nodes),
    ('MAX_LABELS', run_max_labels),
    ('MAX_ZCODE_SIZE', run_max_zcode_size),
    ('OMIT_UNUSED_ROUTINES', run_omit_unused_routines),
    ('OMIT_SYMBOL_TABLE', run_omit_symbol_table),
    ('ZCODE_FILE_END_PADDING', run_file_end_padding),
    ]

test_map = dict(test_catalog)

if (opts.listtests):
    print('Tests in this suite:')
    for (key, func) in test_catalog:
        print(' ', key)
    sys.exit(-1)

if opts.alignment not in (1, 4, 16):
    print('Alignment must be 1, 4, or 16.')
    sys.exit(-1)

if not os.path.exists(opts.binary):
    print('Inform binary not found:', opts.binary)
    sys.exit(-1)

if not os.path.exists('build'):
    os.mkdir('build')

if (not args):
    args = [ key for (key, func) in test_catalog ]

for key in args:
    key = key.upper()
    set_testname(key)
    func = test_map.get(key)
    if (not func):
        error(None, 'No such test!')
        continue
    func()
    
print()

if (not errorlist):
    print('All tests passed.')
else:
    print('%d test failures!' % (len(errorlist),))
    for (test, label, msg) in errorlist:
        print('  %s (%s): %s' % (test, label, msg))

