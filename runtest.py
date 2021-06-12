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
# NUM_ATTR_BYTES
# MAX_DICT_ENTRIES
# DICT_WORD_SIZE
# DICT_CHAR_SIZE (glulx)
# HASH_TAB_SIZE
# MAX_LINESPACE
# MAX_LINK_DATA_SIZE
# MAX_LOCAL_VARIABLES (glulx)
# MAX_SOURCE_FILES
# MAX_TRANSCRIPT_SIZE
# MAX_UNICODE_CHARS (glulx)
# MAX_VERBSPACE

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
popt.add_option('-l', '--list',
    action='store_true', dest='listtests',
    help='display list of tests')

(opts, args) = popt.parse_args()

testname = '???'
errorlist = []

def compile(srcfile, destfile=None, glulx=False, zversion=None, includedir=None, moduledir=None, memsettings={}, define={}, debug=False, strict=True, economy=False, makeabbrevs=False, bigmem=False, makemodule=False, usemodules=False):
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
    - economy turns on economy (abbreviation) mode (-e)
    - makeabbrevs generates abbreviations (-u)
    - bigmem turns on large-memory (odd-even) mode for V6/7 (-B)
    - makemodule generates a .m5 link module (-M)
    - usemodules uses modules for verblibm/parserm (-U)
    """
    argls = [ opts.binary ]
    if includedir:
        argls.append('+include_path='+includedir)
    if moduledir:
        argls.append('+module_path='+moduledir)
    argls.append('+code_path=build')

    # Arguments which will be displayed in the results.
    showargs = []
    
    if (glulx):
        showargs.append('-G')
    elif (zversion):
        showargs.append('-v%d' % (zversion,))
    for (key, val) in list(memsettings.items()):
        showargs.append('$%s=%s' % (key, val))
    for (key, val) in list(define.items()):
        if val is None:
            showargs.append('$#%s' % (key,))
        else:
            showargs.append('$#%s=%d' % (key, val))
    if debug:
        showargs.append('-D')
    if not strict:
        showargs.append('-~S')
    if economy:
        showargs.append('-e')
    if makeabbrevs:
        showargs.append('-u')
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
    print('Running:', ' '.join(argls))

    env = dict(os.environ)
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
                
                match = re.match(r'(?:"[^"]*", )?line (\d+): Fatal error:', ln)
                if (match):
                    outlines += 1
                    self.errors = 1
                    ln = ln[ match.end() : ].strip()
                    match = re.match('The memory setting (\S+)', ln)
                    if (match):
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

    def is_ok(self, md5=None, abbreviations=None, warnings=None):
        """ Assert that the compile was successful.
        If the md5 argument is passed, we check that the resulting binary
        matches.
        If the abbreviations argument passed, we check that the compile
        produced those abbreviations. (Not necessarily in the same order.)
        If the warnings argument is passed, we check that exactly that
        many warnings were generated.
        """
        if (self.status == Result.OK):
            if not os.path.exists(self.filename):
                error(self, 'Game file does not exist: %s' % (self.filename,))
                print('*** TEST FAILED ***')
                return False
            if md5:
                val = self.canonical_checksum()
                if val != md5:
                    error(self, 'Game file mismatch: %s is not %s' % (val, md5,))
                    print('*** TEST FAILED ***')
                    return False
            if abbreviations is not None:
                s1 = set(abbreviations)
                s2 = set(self.abbreviations)
                if s1 != s2:
                    error(self, 'Abbreviations list mismatch: missing %s, extra %s' % (list(s1-s2), list(s2-s1),))
                    print('*** TEST FAILED ***')
                    return False
            if warnings is not None:
                if self.warnings != warnings:
                    error(self, 'Warnings mismatch: expected %s but got %s' % (warnings, self.warnings,))
                    print('*** TEST FAILED ***')
                    return False
            return True
        error(self, 'Should be ok, but was: %s' % (self,))
        print('*** TEST FAILED ***')
        return False

    def is_memsetting(self, val):
        """ Assert that the compile ended with an "increase $SETTING"
        error (recognizable by I7).
        """
        if (self.status == Result.ERROR and self.memsetting == val):
            return True
        error(self, 'Should be error (%s), but was: %s' % (val, self,))
        print('*** TEST FAILED ***')
        return False

    def is_error(self, warnings=None):
        """ Assert that the compile failed, but *not* with an
        "increase $SETTING" error.
        """
        if (self.status == Result.ERROR and not self.memsetting):
            if warnings is not None:
                if self.warnings != warnings:
                    error(self, 'Warnings mismatch: expected %s but got %s' % (warnings, self.warnings,))
                    print('*** TEST FAILED ***')
                    return False
            return True
        error(self, 'Should be error, but was: %s' % (self,))
        print('*** TEST FAILED ***')
        return False

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
    
    res = compile('i7-min-6G60.inf')
    res.is_ok(md5='72f858186e126859010cbbca40602ce3')

    res = compile('i7-min-6G60.inf', zversion=8)
    res.is_ok(md5='5feea90b2cf68a270d33795245008383')

    res = compile('i7-min-6G60.inf', glulx=True)
    res.is_ok(md5='e9d3046de7a45028812aad9d5a132d32')

    res = compile('i7-min-6M62-z.inf', zversion=8)
    res.is_ok(md5='5d684cd1f5028c923ec16fe4761ed5c9')

    res = compile('i7-min-6M62-g.inf', glulx=True)
    res.is_ok(md5='ccb67fdaf4a272dfd4b829cc4f2202f6')

    res = compile('Advent.inf', includedir='i6lib-611')
    res.is_ok(md5='453977372e150037f9f3f93cdf847e35', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8)
    res.is_ok(md5='04c6ff040938ad7e410da6f0c0bbf093', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True)
    res.is_ok(md5='e603310679dfcb3185194dfc85941a73', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8, strict=False)
    res.is_ok(md5='c51d3a8c451bf7c296e4445fdb5f75c3', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True, strict=False)
    res.is_ok(md5='94ba670fc39d1ab92bfdc73a3b50fe90', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8, debug=True)
    res.is_ok(md5='01cfbb8f2ba5266aed0e7f0b5e20455a', warnings=0)

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True, debug=True)
    res.is_ok(md5='5135238ba7ef10a868a236aa914ae7f1', warnings=0)

    res = compile('cloak-metro84-v3test.inf', zversion=3, economy=False)
    res.is_ok(md5='52dc4fa45ad64e85c8a211833b083009')

    res = compile('cloak-metro84-v3test.inf', zversion=4, economy=False)
    res.is_ok(md5='64c9fc5d9de47be75f2cacf0a1a40b36')

    res = compile('cloak-metro84-v3test.inf', zversion=5, economy=False)
    res.is_ok(md5='010d54a6ff19170a6674caabcd6fac29')

    res = compile('cloak-metro84-v3test.inf', zversion=3, economy=True)
    res.is_ok(md5='a378cd678a18d41308f675ec720e919e')

    res = compile('cloak-metro84-v3test.inf', zversion=4, economy=True)
    res.is_ok(md5='afaa158cf037c0c8b217d762e47a936a')

    res = compile('cloak-metro84-v3test.inf', zversion=5, economy=True)
    res.is_ok(md5='44a69b2c9342a17356e54de151fb4688')

    res = compile('library_of_horror.inf', includedir='punylib-16', zversion=3)
    res.is_ok(md5='e4c564649bc470901ddaf9c2df4ba031')

    res = compile('library_of_horror.inf', includedir='punylib-16', zversion=3, memsettings={'OMIT_UNUSED_ROUTINES':1})
    res.is_ok(md5='148e77a6c596ff59734a9e14f8edde81')


def run_dict_test():
    res = compile('dict-size-v3test.inf', zversion=3)
    res.is_ok(md5='1be758056fc55b2c67f4dd1ce69e6dce')

    res = compile('dict-size-v3test.inf', zversion=5)
    res.is_ok(md5='09300a2de87d8f8fee3d5a79d151aff4')

    res = compile('dict-cutoff-v3test.inf', strict=False, zversion=3)
    res.is_ok(md5='a1e1de6b77a08070f474e5175f86be44')

    res = compile('dict-cutoff-v3test.inf', strict=False, zversion=4)
    res.is_ok(md5='24d79e2b61cd0303aefee138d4ac7072')

    res = compile('dict-cutoff-v3test.inf', strict=False, zversion=5)
    res.is_ok(md5='8ef389de3680e6959ac19ae4abcee86f')

    res = compile('dict-cutoff-alttest.inf', strict=False, zversion=4)
    res.is_ok(md5='96b7be57a011a6357149c29cf840de32')

    res = compile('dict-cutoff-alttest.inf', strict=False, zversion=5)
    res.is_ok(md5='7f00da7b281c32d2a2bf514eda1b7c39')

    res = compile('dict-cutoff-alttest.inf', strict=False, zversion=8)
    res.is_ok(md5='babab7a13980537b30e01d53885e4691')


def run_directives_test():
    res = compile('staticarraytest.inf')
    res.is_ok(md5='736f5df15951398ec41b0d05e4280cce')

    res = compile('staticarraytest.inf', glulx=True)
    res.is_ok(md5='45b07b21aa4ff3ba2563bdbfd134dd1a')

    res = compile('undefdirectivetest.inf')
    res.is_ok(md5='de2f2e32f82bf14a4178f3a992762e6b')

    res = compile('undefdirectivetest.inf', glulx=True)
    res.is_ok(md5='cb28a5edcd681dfde63e472ac2542a95')

    res = compile('replacerenametest.inf', includedir='src')
    res.is_ok(md5='20f77c3bc7002792f218a345f547b91c')

    res = compile('replacerenametest.inf', includedir='src', glulx=True)
    res.is_ok(md5='3626d00770bcb1c6c9adfe476f53f943')

    res = compile('replacerecursetest.inf')
    res.is_ok(md5='f9abd6adec9bd6cfdd215fccb1abf22b')

    res = compile('replacerecursetest.inf', glulx=True)
    res.is_ok(md5='e6ff7304a967ab9cae5b99da9e7a3df1')

    res = compile('dictflagtest.inf')
    res.is_ok(md5='494cc7406f0d8183e9c2621ab8c0d204')

    res = compile('dictflagtest.inf', glulx=True)
    res.is_ok(md5='438aead86360423e32aecb2dda8e2341')

    res = compile('actionextension.inf')
    res.is_ok(md5='8434dd954b155675ec9a853052b5a5bc')

    res = compile('actionextension.inf', glulx=True)
    res.is_ok(md5='a90ea20de4c538312842ef1c5a5ee932')

    res = compile('internaldirecttest.inf')
    res.is_ok(md5='191fd5acfff6e1208b04f0d6d178f8eb')

    res = compile('internaldirecttest.inf', glulx=True)
    res.is_ok(md5='69666314dc31e270809d11f2ee9cebd6')

    res = compile('ifelsedirecttest.inf')
    res.is_ok(md5='33dfb4452ebb69030ae6e7c3db2f0833')

    res = compile('ifelsedirecttest.inf', glulx=True)
    res.is_ok(md5='c9f1ab6a8dfba69f4bb2746c20c3fbbb')

    res = compile('classordertest.inf')
    res.is_ok(md5='d065c980637c8531133e75bf040e1731')

    res = compile('classordertest.inf', glulx=True)
    res.is_ok(md5='2844efeeff5ff0842b7185a56e80f6dd')

    res = compile('classcopytest.inf')
    res.is_ok(md5='6dc016b201b6591501911ccac02e152c')

    res = compile('classcopytest.inf', glulx=True)
    res.is_ok(md5='aef9bdc052d269b239a6ddbd81f62160')

    res = compile('forwardproptest.inf')
    res.is_ok(md5='d2a0621f1b3703523a9e0e00da8270d6')

    res = compile('forwardproptest.inf', strict=False)
    res.is_ok(md5='b181a2d7edd1d8188e0575767f53a886')

    res = compile('forwardproptest.inf', glulx=True)
    res.is_ok(md5='665d237c43611454965e1b680f12d596')

    res = compile('forwardproptest.inf', glulx=True, strict=False)
    res.is_ok(md5='5592d67a77e3fda229465e2c799fb213')


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

    
def run_defineopt_test():
    res = compile('defineopttest.inf')
    res.is_ok(md5='ccb42f85b0f12fa19fc34ba46c6f91a9')

    res = compile('defineopttest.inf', debug=True)
    res.is_ok(md5='6f23ba9a571008507addca8d474adc68')

    res = compile('defineopttest.inf', define={ 'DEBUG':None })
    res.is_ok(md5='6f23ba9a571008507addca8d474adc68')

    res = compile('defineopttest.inf', define={ 'DEBUG':0 })
    res.is_ok(md5='6f23ba9a571008507addca8d474adc68')

    res = compile('defineopttest.inf', define={ 'FOO':26, 'BAR':-923, 'BAZ':None, 'QUUX':123, 'MUM':-1, 'NERTZ':99999 })
    res.is_ok(md5='6d114e7ba8015c04e3ccd9d9356ca12b')

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
    res.is_ok(md5='ccb42f85b0f12fa19fc34ba46c6f91a9')

    res = compile('defineopttest.inf', define={ 'XFOO':3, 'xfoo':3 })
    res.is_ok(md5='ccb42f85b0f12fa19fc34ba46c6f91a9')

    res = compile('defineopttest.inf', glulx=True)
    res.is_ok(md5='a4462c91fbabdafc3999bc7128ffda5c')

    res = compile('defineopttest.inf', glulx=True, debug=True)
    res.is_ok(md5='ba60f7883b7af76f05942aa92e348d87')

    res = compile('defineopttest.inf', glulx=True, define={ 'DEBUG':None })
    res.is_ok(md5='ba60f7883b7af76f05942aa92e348d87')

    res = compile('defineopttest.inf', glulx=True, define={ 'DEBUG':0 })
    res.is_ok(md5='ba60f7883b7af76f05942aa92e348d87')

    res = compile('defineopttest.inf', glulx=True, define={ 'Wordsize':4 })
    res.is_ok(md5='a4462c91fbabdafc3999bc7128ffda5c')


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
    res.is_ok()

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z5', define={ 'FORWARD_CONSTANT':5 })
    res.is_ok()

    res = compile('fwconst_version_test.inf', destfile='fwconst_version_test.z8', define={ 'FORWARD_CONSTANT':8 })
    res.is_ok()

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


def run_modules_test():
    # parserm.inf and verblibm.inf are copies of the library header files in i6lib-611. (The test framework expects them to be in the src directory.)
    
    res = compile('parserm.inf', includedir='i6lib-611', moduledir='build', makemodule=True)
    res.is_ok(md5='e411c79916ae0f9cd8408df5766c5fd7')
    
    res = compile('verblibm.inf', includedir='i6lib-611', moduledir='build', makemodule=True)
    res.is_ok(md5='3d381fd6590fee842d5b75f2a3abbddb')

    # Now build Advent using the two modules we just generated.
    res = compile('Advent.inf', includedir='i6lib-611', moduledir='build', usemodules=True)
    res.is_ok(md5='47a9cc9ac052d2bac220e617d2ff6b7c')


def run_warnings_test():
    res = compile('typewarningtest.inf')
    res.is_ok(warnings=27)
    
    res = compile('typewarningtest.inf', glulx=True)
    res.is_ok(warnings=29)
    

def run_make_abbreviations_test():
    res = compile('abbrevtest.inf', makeabbrevs=True)
    res.is_ok(abbreviations=['. ', ', ', '**]', "='@", ' the', 'tried to print (', 'string', 'objec', ' on something n', ' here', ' tha', "31'.^", 'ing', ' to ', 'tribute', '~ o', 'lass', 'ate', 'ther', 'which', 'for', ': 0', "16'", 'ave', 'loop', 'can', 'mber', 'tion', 'is n', 'cre', 'use', 'ed ', 'at ', 'or ', 'ot ', 'has', "00'", "01'", '-- ', 'est', 'er ', 'hall ', 'is ', 'in ', 'we ', 'ead', 'of ', 'out', 'rem', ' a ', 'not', 'nse', 'ove', ' de', ' to', ' it', ' wh', ' us', 'se ', 'de '])
    
    res = compile('include_english.inf', includedir='i6lib-611', makeabbrevs=True)
    res.is_ok(abbreviations=['. ', ', ', 'You ', "'t ", 'ing ', '**]', 'The', 'That', 'you can', 'someth', '_to)', 'closed', 're ', 'bject', 'already ', 'But ', 's no', 'which ', ' to ', 'ing', 'can', "You'", 'ome', 'the', 'your', 'Command', 't of', 'achieve', 'Language', 'scrip', 'have', 'tion', 'ou aren', 'seem', 'nd ', 'you', 'at ', 'noth', 'see ', 'ose ', 'ed.', 'of ', 'ed ', 'ch ', 'ect', 'not ', 'Not', 'in ', 'read', 'would ', 'on ', 'You', 'ere.', 'int', 'provid', 'est', 'empt', 'lock', '~ or ', 'ight', 'is ', 've ', 'me ', 'first'])

    
def run_max_ifdef_stack():
    # Fixed limit; no memory setting to change.
    
    res = compile('max_ifdef_stack_32.inf')
    res.is_ok();

    res = compile('max_ifdef_stack_33.inf')
    res.is_error();
    
    
def run_max_inclusion_depth():
    res = compile('max_inclusion_depth_test.inf', includedir='src', memsettings={'MAX_INCLUSION_DEPTH':5})
    res.is_memsetting('MAX_INCLUSION_DEPTH')

    res = compile('max_inclusion_depth_test.inf', includedir='src', memsettings={'MAX_INCLUSION_DEPTH':6})
    res.is_ok()
    
    res = compile('max_inclusion_depth_test.inf', includedir='src', memsettings={'MAX_INCLUSION_DEPTH':5}, glulx=True)
    res.is_memsetting('MAX_INCLUSION_DEPTH')

    res = compile('max_inclusion_depth_test.inf', includedir='src', memsettings={'MAX_INCLUSION_DEPTH':6}, glulx=True)
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


def run_max_classes():
    res = compile('max_classes_test.inf')
    res.is_ok()

    res = compile('max_classes_test.inf', glulx=True)
    res.is_ok()


def run_max_arrays():
    res = compile('max_arrays_test.inf', memsettings={'MAX_ARRAYS':149})
    res.is_memsetting('MAX_ARRAYS')

    res = compile('max_arrays_test.inf', memsettings={'MAX_ARRAYS':150})
    res.is_ok()

    res = compile('max_arrays_test.inf', memsettings={'MAX_ARRAYS':149}, glulx=True)
    res.is_memsetting('MAX_ARRAYS')

    res = compile('max_arrays_test.inf', memsettings={'MAX_ARRAYS':150}, glulx=True)
    res.is_ok()

    res = compile('max_arrays_test_2.inf', memsettings={'MAX_ARRAYS':149})
    res.is_memsetting('MAX_ARRAYS')

    res = compile('max_arrays_test_2.inf', memsettings={'MAX_ARRAYS':150})
    res.is_ok()

    res = compile('max_arrays_test_2.inf', memsettings={'MAX_ARRAYS':149}, glulx=True)
    res.is_memsetting('MAX_ARRAYS')

    res = compile('max_arrays_test_2.inf', memsettings={'MAX_ARRAYS':150}, glulx=True)
    res.is_ok()

    res = compile('max_arrays_test_3.inf', memsettings={'MAX_ARRAYS':99})
    res.is_memsetting('MAX_ARRAYS')

    res = compile('max_arrays_test_3.inf', memsettings={'MAX_ARRAYS':100})
    res.is_ok()

    res = compile('max_arrays_test_3.inf', memsettings={'MAX_ARRAYS':99}, glulx=True)
    res.is_memsetting('MAX_ARRAYS')

    res = compile('max_arrays_test_3.inf', memsettings={'MAX_ARRAYS':100}, glulx=True)
    res.is_ok()


def run_max_prop_table_size():
    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':10000})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':23592})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':23593})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':23868})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':23869})
    res.is_ok()

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':20000}, glulx=True)
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':52425}, glulx=True)
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':52426}, glulx=True)
    res.is_ok()

    # Glulx uses this setting for individual properties too

    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':52425}, glulx=True)
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':52426}, glulx=True)
    res.is_ok()

    # A single large object can run into this setting too.
    
    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':4000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':40000}, glulx=True)
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':40000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':40000}, glulx=True)
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    # So can a Z-code object's shortname.

    res = compile('large_object_short_name_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':500})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('large_object_short_name_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':582})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('large_object_short_name_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':583})
    res.is_ok()

    res = compile('large_object_short_name_test_2.inf', memsettings={'MAX_PROP_TABLE_SIZE':500})
    res.is_memsetting('MAX_PROP_TABLE_SIZE')

    res = compile('large_object_short_name_test_2.inf', memsettings={'MAX_PROP_TABLE_SIZE':584})
    res.is_error()


def run_max_indiv_prop_table_size():
    # We include some extra MAX_INDIV_PROP_TABLE_SIZE values which triggered
    # memory errors in I632N.
    
    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_INDIV_PROP_TABLE_SIZE':10000})
    res.is_memsetting('MAX_INDIV_PROP_TABLE_SIZE')

    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_INDIV_PROP_TABLE_SIZE':23263})
    res.is_memsetting('MAX_INDIV_PROP_TABLE_SIZE')

    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_INDIV_PROP_TABLE_SIZE':23264})
    res.is_memsetting('MAX_INDIV_PROP_TABLE_SIZE')
    
    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_INDIV_PROP_TABLE_SIZE':23431})
    res.is_memsetting('MAX_INDIV_PROP_TABLE_SIZE')

    res = compile('max_indiv_prop_table_size_test.inf', memsettings={'MAX_INDIV_PROP_TABLE_SIZE':23432})
    res.is_ok()

    # Glulx does not use this setting, so no Glulx tests.

    
def run_max_obj_prop_table_size():
    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':4000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':4000}, glulx=True)
    res.is_memsetting('MAX_OBJ_PROP_TABLE_SIZE')

    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':40000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':4000}, glulx=True)
    res.is_memsetting('MAX_OBJ_PROP_TABLE_SIZE')

    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':100000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':10000}, glulx=True)
    res.is_memsetting('MAX_OBJ_PROP_TABLE_SIZE')

    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':100000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':19999}, glulx=True)
    res.is_memsetting('MAX_OBJ_PROP_TABLE_SIZE')

    res = compile('max_obj_prop_table_size_test.inf', memsettings={'MAX_PROP_TABLE_SIZE':100000, 'MAX_OBJ_PROP_COUNT':110, 'MAX_OBJ_PROP_TABLE_SIZE':20000}, glulx=True)
    res.is_ok()


def run_max_obj_prop_count():
    res = compile('max_obj_prop_count_test.inf', memsettings={'MAX_OBJ_PROP_COUNT':200}, glulx=True)
    res.is_memsetting('MAX_OBJ_PROP_COUNT')

    res = compile('max_obj_prop_count_test.inf', memsettings={'MAX_OBJ_PROP_COUNT':201}, glulx=True)
    res.is_ok()


def run_max_global_variables():
    # In Z-code, at most 233 globals are available, and you can't raise the
    # limit.
    res = compile('max_global_variables_test.inf')
    res.is_ok()
    
    res = compile('max_global_variables_test_2.inf')
    res.is_error()
    
    res = compile('max_global_variables_test_2.inf', memsettings={'MAX_GLOBAL_VARIABLES':100}, glulx=True)
    res.is_memsetting('MAX_GLOBAL_VARIABLES')

    res = compile('max_global_variables_test_2.inf', memsettings={'MAX_GLOBAL_VARIABLES':510}, glulx=True)
    res.is_memsetting('MAX_GLOBAL_VARIABLES')

    res = compile('max_global_variables_test_2.inf', memsettings={'MAX_GLOBAL_VARIABLES':511}, glulx=True)
    res.is_ok()


def run_max_static_data():
    # We were getting overflow errors on odd values, so we have a lot of test
    # cases here.
    
    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':5000})
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':20477})
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':20478})
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':20479})
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':20480})
    res.is_ok()

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':20481})
    res.is_ok()

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':5000}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42042}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42043}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42044}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42045}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42046}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42047}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test.inf', memsettings={'MAX_STATIC_DATA':42048}, glulx=True)
    res.is_ok()

    res = compile('max_static_data_test_2.inf', memsettings={'MAX_STATIC_DATA':19999})
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test_2.inf', memsettings={'MAX_STATIC_DATA':20000})
    res.is_ok()

    res = compile('max_static_data_test_2.inf', memsettings={'MAX_STATIC_DATA':39999}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test_2.inf', memsettings={'MAX_STATIC_DATA':40000}, glulx=True)
    res.is_ok()

    res = compile('max_static_data_test_3.inf', memsettings={'MAX_STATIC_DATA':20479, 'MAX_ARRAYS':200})
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test_3.inf', memsettings={'MAX_STATIC_DATA':20480, 'MAX_ARRAYS':200})
    res.is_ok()

    res = compile('max_static_data_test_3.inf', memsettings={'MAX_STATIC_DATA':42047, 'MAX_ARRAYS':200}, glulx=True)
    res.is_memsetting('MAX_STATIC_DATA')

    res = compile('max_static_data_test_3.inf', memsettings={'MAX_STATIC_DATA':42048, 'MAX_ARRAYS':200}, glulx=True)
    res.is_ok()


def run_max_num_static_strings():
    # Glulx only

    res = compile('static_text_test.inf', memsettings={'MAX_NUM_STATIC_STRINGS':271}, glulx=True)
    res.is_memsetting('MAX_NUM_STATIC_STRINGS')

    res = compile('static_text_test.inf', memsettings={'MAX_NUM_STATIC_STRINGS':272}, glulx=True)
    res.is_ok()

    
def run_max_qtext_size():
    # Push MAX_STATIC_STRINGS high so that we don't run into it. That's
    # a different test.
    
    res = compile('max_static_strings_test.inf', memsettings={'MAX_STATIC_STRINGS':30000, 'MAX_QTEXT_SIZE':2000})
    res.is_memsetting('MAX_QTEXT_SIZE')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_STATIC_STRINGS':30000, 'MAX_QTEXT_SIZE':8000})
    res.is_memsetting('MAX_QTEXT_SIZE')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_STATIC_STRINGS':30000, 'MAX_QTEXT_SIZE':8001})
    res.is_ok()

    res = compile('max_static_strings_test.inf', memsettings={'MAX_STATIC_STRINGS':60000, 'MAX_QTEXT_SIZE':2000}, glulx=True)
    res.is_memsetting('MAX_QTEXT_SIZE')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_STATIC_STRINGS':60000, 'MAX_QTEXT_SIZE':8000}, glulx=True)
    res.is_memsetting('MAX_QTEXT_SIZE')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_STATIC_STRINGS':60000, 'MAX_QTEXT_SIZE':8001}, glulx=True)
    res.is_ok()

    
def run_max_static_strings():
    # The compiler ensures that MAX_STATIC_STRINGS is (at least) twice
    # MAX_QTEXT_SIZE.
    
    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':16002})
    res.is_memsetting('MAX_STATIC_STRINGS')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':21333})
    res.is_memsetting('MAX_STATIC_STRINGS')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':21335})
    res.is_memsetting('MAX_STATIC_STRINGS')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':21336})
    res.is_ok()

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':16002}, glulx=True)
    res.is_memsetting('MAX_STATIC_STRINGS')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':48000}, glulx=True)
    res.is_memsetting('MAX_STATIC_STRINGS')

    res = compile('max_static_strings_test.inf', memsettings={'MAX_QTEXT_SIZE':8001, 'MAX_STATIC_STRINGS':48001}, glulx=True)
    res.is_ok()


def run_max_low_strings():
    # Only meaningful for Z-code.
    
    res = compile('max_low_strings_test.inf', memsettings={'MAX_LOW_STRINGS':1000})
    res.is_memsetting('MAX_LOW_STRINGS')

    res = compile('max_low_strings_test.inf', memsettings={'MAX_LOW_STRINGS':3439})
    res.is_memsetting('MAX_LOW_STRINGS')

    res = compile('max_low_strings_test.inf', memsettings={'MAX_LOW_STRINGS':3440})
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

    res = compile('max_dynamic_strings_test_at63.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_at64.inf', glulx=True, memsettings={})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_str31.inf', memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str32.inf', memsettings={})
    res.is_memsetting('MAX_DYNAMIC_STRINGS')

    res = compile('max_dynamic_strings_test_str31.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str32.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str63.inf', glulx=True, memsettings={})
    res.is_ok()

    res = compile('max_dynamic_strings_test_str64.inf', glulx=True, memsettings={})
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

    res = compile('max_dynamic_strings_test_at99.inf', glulx=True, memsettings={'MAX_DYNAMIC_STRINGS':100})
    res.is_ok()

    
def run_max_abbrevs():
    res = compile('abbrevtest.inf')
    res.is_ok(md5='037c643cd38396fc3870119bf49b69f6')
    
    res = compile('abbrevtest.inf', glulx=True)
    res.is_ok(md5='ab49bb2007e82436816831f36658d446')
    
    res = compile('abbrevtest.inf', economy=True)
    res.is_ok(md5='dd03eb8c46343be4991b139926a1c296')
    
    res = compile('abbrevtest.inf', glulx=True, economy=True)
    res.is_ok(md5='3bb3d7ef0a77294c14099e83b9770807')
    
    res = compile('max_abbrevs_test_64.inf', memsettings={})
    res.is_ok()

    res = compile('max_abbrevs_test_64.inf', memsettings={'MAX_ABBREVS':63})
    res.is_error

    res = compile('max_abbrevs_test_32.inf', memsettings={'MAX_ABBREVS':32})
    res.is_ok()

    res = compile('max_abbrevs_test_32.inf', memsettings={'MAX_ABBREVS':31})
    res.is_error()

    res = compile('max_abbrevs_test_96.inf', memsettings={'MAX_ABBREVS':96})
    res.is_ok()

    res = compile('max_abbrevs_test_96.inf', memsettings={'MAX_ABBREVS':95})
    res.is_error()

    res = compile('max_abbrevs_test_96.inf', memsettings={'MAX_DYNAMIC_STRINGS':0})
    res.is_ok()

    res = compile('max_abbrevs_test_96.inf', memsettings={'MAX_DYNAMIC_STRINGS':1})
    res.is_error()

    res = compile('max_abbrevs_test_100.inf', memsettings={'MAX_ABBREVS':96})
    res.is_error()

    res = compile('max_abbrevs_test_64.inf', glulx=True)
    res.is_ok()

    res = compile('max_abbrevs_test_32.inf', glulx=True)
    res.is_ok()

    res = compile('max_abbrevs_test_96.inf', glulx=True)
    res.is_ok()

    res = compile('max_abbrevs_test_100.inf', glulx=True)
    res.is_ok()


def run_max_verb_word_size():
    # Fixed limit; no memory setting to change.
    
    res = compile('max_verb_word_size.inf')
    res.is_ok()

    res = compile('max_verb_word_size_2.inf')
    res.is_error()
    
    res = compile('max_verb_word_size.inf', glulx=True)
    res.is_ok()

    res = compile('max_verb_word_size_2.inf', glulx=True)
    res.is_error()


def run_max_lines_per_verb():
    # Fixed limit; no memory setting to change.
    
    res = compile('max_lines_per_verb_32.inf')
    res.is_ok()

    res = compile('max_lines_per_verb_33.inf')
    res.is_error()

    
def run_max_verb_synonyms():
    # Fixed limit; no memory setting to change.
    
    res = compile('max_verb_synonyms_32.inf')
    res.is_ok();

    res = compile('max_verb_synonyms_33.inf')
    res.is_error();
    
    
def run_max_verbs():
    res = compile('max_verbs.inf')
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs.inf', memsettings={'MAX_VERBS':254})
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs.inf', memsettings={'MAX_VERBS':255})
    res.is_ok()
    
    res = compile('max_verbs.inf', memsettings={'MAX_VERBS':256})
    res.is_error()
    
    res = compile('max_verbs.inf', glulx=True)
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs.inf', memsettings={'MAX_VERBS':254}, glulx=True)
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs.inf', memsettings={'MAX_VERBS':255}, glulx=True)
    res.is_ok()
    
    res = compile('max_verbs.inf', memsettings={'MAX_VERBS':256}, glulx=True)
    res.is_ok()
    
    res = compile('max_verbs_2.inf', memsettings={'MAX_VERBS':255})
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs_2.inf', memsettings={'MAX_VERBS':255}, glulx=True)
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs_2.inf', memsettings={'MAX_VERBS':259}, glulx=True)
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs_2.inf', memsettings={'MAX_VERBS':260}, glulx=True)
    res.is_ok()
    
    res = compile('max_verbs_3.inf', memsettings={'MAX_VERBS':255})
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs_3.inf', memsettings={'MAX_VERBS':255}, glulx=True)
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs_3.inf', memsettings={'MAX_VERBS':259}, glulx=True)
    res.is_memsetting('MAX_VERBS')
    
    res = compile('max_verbs_3.inf', memsettings={'MAX_VERBS':260}, glulx=True)
    res.is_ok()
    
    
def run_max_actions():
    res = compile('max_actions.inf')
    res.is_memsetting('MAX_ACTIONS')

    res = compile('max_actions.inf', memsettings={'MAX_ACTIONS':219})
    res.is_memsetting('MAX_ACTIONS')

    res = compile('max_actions.inf', memsettings={'MAX_ACTIONS':220})
    res.is_ok()

    res = compile('max_actions.inf', glulx=True)
    res.is_memsetting('MAX_ACTIONS')

    res = compile('max_actions.inf', memsettings={'MAX_ACTIONS':219}, glulx=True)
    res.is_memsetting('MAX_ACTIONS')

    res = compile('max_actions.inf', memsettings={'MAX_ACTIONS':220}, glulx=True)
    res.is_ok()

    
def run_max_adjectives():
    res = compile('max_adjectives.inf')
    res.is_memsetting('MAX_ADJECTIVES')

    res = compile('max_adjectives.inf', memsettings={'MAX_ADJECTIVES':99})
    res.is_memsetting('MAX_ADJECTIVES')

    res = compile('max_adjectives.inf', memsettings={'MAX_ADJECTIVES':100})
    res.is_ok()

    # Glulx uses Grammar__Version 2, so adjectives are not used.
    res = compile('max_adjectives.inf', glulx=True)
    res.is_ok()

    res = compile('max_adjectives_2.inf')
    res.is_ok()

    res = compile('max_adjectives_2.inf', memsettings={'MAX_ADJECTIVES':3})
    res.is_ok()

    res = compile('max_adjectives_2.inf', glulx=True)
    res.is_ok()

    
def run_max_expression_nodes():
    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':42})
    res.is_memsetting('MAX_EXPRESSION_NODES')
    
    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':43})
    res.is_ok()

    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':42}, glulx=True)
    res.is_memsetting('MAX_EXPRESSION_NODES')
    
    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':43}, glulx=True)
    res.is_ok()


def run_max_labels():
    res = compile('max_labels_test.inf')
    res.is_memsetting('MAX_LABELS')
    
    res = compile('max_labels_test.inf', memsettings={'MAX_LABELS':1099})
    res.is_memsetting('MAX_LABELS')
    
    res = compile('max_labels_test.inf', memsettings={'MAX_LABELS':1100})
    res.is_ok()
    
    res = compile('max_labels_test.inf', glulx=True)
    res.is_memsetting('MAX_LABELS')
    
    res = compile('max_labels_test.inf', memsettings={'MAX_LABELS':1099}, glulx=True)
    res.is_memsetting('MAX_LABELS')
    
    res = compile('max_labels_test.inf', memsettings={'MAX_LABELS':1100}, glulx=True)
    res.is_ok()
    
def run_max_zcode_size():
    res = compile('large_opcode_text_test.inf', memsettings={'MAX_ZCODE_SIZE':10000, 'MAX_QTEXT_SIZE':8001})
    res.is_memsetting('MAX_ZCODE_SIZE')

    res = compile('large_opcode_text_test.inf', memsettings={'MAX_ZCODE_SIZE':21336, 'MAX_QTEXT_SIZE':8001})
    res.is_memsetting('MAX_ZCODE_SIZE')

    res = compile('large_opcode_text_test.inf', memsettings={'MAX_ZCODE_SIZE':21337, 'MAX_QTEXT_SIZE':8001})
    res.is_ok()

    ### Many more tests should be done here.


def run_omit_unused_routines():
    res = compile('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1})
    res.is_ok()
    res.is_ok(md5='6e81c775d77ca5a05917f782eb502981')

    res = compile('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True)
    res.is_ok()
    res.is_ok(md5='b4754e75f23e1d6bf922e0fa6f236177')


test_catalog = [
    ('CHECKSUM', run_checksum_test),
    ('DICT', run_dict_test),
    ('DIRECTIVES', run_directives_test),
    ('DEBUGFLAG', run_debugflag_test),
    ('DEFINEOPT', run_defineopt_test),
    ('FWCONST', run_fwconst_test),
    ('MODULES', run_modules_test),
    ('WARNINGS', run_warnings_test),
    ('MAKE_ABBREVIATIONS', run_make_abbreviations_test),
    ('MAX_IFDEF_STACK', run_max_ifdef_stack),
    ('MAX_INCLUSION_DEPTH', run_max_inclusion_depth),
    ('MAX_SYMBOLS', run_max_symbols),
    ('SYMBOLS_CHUNK_SIZE', run_symbols_chunk_size),
    ('MAX_OBJECTS', run_max_objects),
    ('MAX_CLASSES', run_max_classes),
    ('MAX_ARRAYS', run_max_arrays),
    ('MAX_PROP_TABLE_SIZE', run_max_prop_table_size),
    ('MAX_INDIV_PROP_TABLE_SIZE', run_max_indiv_prop_table_size),
    ('MAX_OBJ_PROP_TABLE_SIZE', run_max_obj_prop_table_size),
    ('MAX_OBJ_PROP_COUNT', run_max_obj_prop_count),
    ('MAX_GLOBAL_VARIABLES', run_max_global_variables),
    ('MAX_STATIC_DATA', run_max_static_data),
    ('MAX_NUM_STATIC_STRINGS', run_max_num_static_strings),
    ('MAX_QTEXT_SIZE', run_max_qtext_size),
    ('MAX_STATIC_STRINGS', run_max_static_strings),
    ('MAX_LOW_STRINGS', run_max_low_strings),
    ('MAX_DYNAMIC_STRINGS', run_max_dynamic_strings),
    ('MAX_ABBREVS', run_max_abbrevs),
    ('MAX_VERBS', run_max_verbs),
    ('MAX_VERB_WORD_SIZE', run_max_verb_word_size),
    ('MAX_VERB_SYNONYMS', run_max_verb_synonyms),
    ('MAX_LINES_PER_VERB', run_max_lines_per_verb),
    ('MAX_ACTIONS', run_max_actions),
    ('MAX_ADJECTIVES', run_max_adjectives),
    ('MAX_EXPRESSION_NODES', run_max_expression_nodes),
    ('MAX_LABELS', run_max_labels),
    ('MAX_ZCODE_SIZE', run_max_zcode_size),
    ('OMIT_UNUSED_ROUTINES', run_omit_unused_routines),
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

