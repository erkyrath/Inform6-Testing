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
# MAX_ABBREVS
# MAX_ACTIONS
# MAX_ADJECTIVES
# NUM_ATTR_BYTES
# MAX_DICT_ENTRIES
# DICT_WORD_SIZE
# DICT_CHAR_SIZE (glulx)
# HASH_TAB_SIZE
# MAX_LABELS
# MAX_LINESPACE
# MAX_LINK_DATA_SIZE
# MAX_LOCAL_VARIABLES (glulx)
# MAX_LOW_STRINGS
# MAX_SOURCE_FILES
# MAX_TRANSCRIPT_SIZE
# MAX_UNICODE_CHARS (glulx)
# MAX_VERBS
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

def compile(srcfile, glulx=False, zversion=None, includedir=None, memsettings={}):
    """Perform one Inform compile, and return a Result object.
    """
    argls = [ opts.binary ]
    if includedir:
        argls.append('+include_path='+includedir)
    argls.append('+code_path=build')
    if (glulx):
        argls.append('-G')
    elif (zversion):
        argls.append('-v%d' % (zversion,))
    for (key, val) in list(memsettings.items()):
        argls.append('$%s=%s' % (key, val))
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
    res = run.wait()
    stdout = run.stdout.read().decode()
    stderr = run.stderr.read().decode()
    res = Result(res, stdout, stderr, srcfile=srcfile, zversion=zversion, glulx=glulx)

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
    
    def __init__(self, retcode, stdout, stderr, srcfile=None, zversion=None, glulx=False):
        self.status = None
        self.filename = None
        self.signame = None
        self.warnings = 0
        self.errors = 0
        self.memsetting = None

        if srcfile is not None:
            if not srcfile.endswith('.inf'):
                raise Exception('srcfile is not a .inf file')
            val = srcfile[ : -4 ]
            suffix = ''
            if not glulx:
                if zversion:
                    suffix = '.z%d' % (zversion,)
                else:
                    suffix = '.z5'
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
            error('Run ended with signal %s' % (signame,))
        else:
            lines = stderr.split('\n')
            for ln in lines:
                inheader = True
                if ('GuardMalloc[' in ln):
                    if (inheader):
                        if re.match('GuardMalloc[^:]*: version [0-9.]*', ln):
                            inheader = False
                        continue
                    error('Apparent libgmalloc error ' + ln)
            
            lines = stdout.split('\n')
            outlines = 0
            for ln in lines:
                
                match = re.match('(?:"[^"]*", )?line (\d+): Fatal error:', ln)
                if (match):
                    outlines += 1
                    self.errors = 1
                    ln = ln[ match.end() : ].strip()
                    match = re.match('The memory setting (\S+)', ln)
                    if (match):
                        self.memsetting = match.group(1)
                    continue
                
                match = re.match('Compiled with (\d+) errors? \(no output\)', ln)
                if (match):
                    outlines += 1
                    self.errors = int(match.group(1))
                    continue
                
                match = re.match('Compiled with (\d+) errors? and (\d+) suppressed warnings? \(no output\)', ln)
                if (match):
                    outlines += 1
                    self.errors = int(match.group(1))
                    self.warnings = int(match.group(2))
                    continue

                match = re.match('Compiled with (\d+) suppressed warnings?', ln)
                if (match):
                    outlines += 1
                    self.warnings = int(match.group(1))
                    continue
                
                match = re.match('Compiled', ln)
                if (match):
                    error('Unmatched "Compiled" line in output: ' + ln)
                    continue

            if (outlines > 1):
                error('Too many "Compiled" lines in output')

            if (retcode == 0):
                self.status = Result.OK
                if (self.errors):
                    error('Run status zero despite %d errors' % (self.errors,))
            else:
                self.status = Result.ERROR
                if (not self.errors):
                    error('Run status nonzero despite no errors')

    def __str__(self):
        if (self.status == Result.SIGNAL):
            return '<Signal ' + self.signame + '>'
        if (self.status == Result.OK):
            res = '<Ok'
        else:
            res = '<Error'
        if (self.errors):
            res = res + ' (%d errors)' % (self.errors,)
        if (self.warnings):
            res = res + ' (%d warnings)' % (self.warnings,)
        if (self.memsetting):
            res = res + ' (%s failed)' % (self.memsetting,)
        return res + '>'

    def is_ok(self, md5=None):
        """ Assert that the compile was successful.
        If the md5 argument is passed, we check that the resulting binary
        matches.
        """
        if (self.status == Result.OK):
            if not os.path.exists(self.filename):
                error('Game file does not exist: %s' % (self.filename,))
                print('*** TEST FAILED ***')
                return False
            if md5:
                infl = open(self.filename, 'rb')
                dat = infl.read()
                infl.close()
                val = hashlib.md5(dat).hexdigest()
                if val != md5:
                    error('Game file mismatch: %s is not %s' % (val, md5,))
                    print('*** TEST FAILED ***')
                    return False
            return True
        error('Should be ok, but was: %s' % (self,))
        print('*** TEST FAILED ***')
        return False

    def is_memsetting(self, val):
        """ Assert that the compile ended with an "increase $SETTING"
        error (recognizable by I7).
        """
        if (self.status == Result.ERROR and self.memsetting == val):
            return True
        error('Should be error (%s), but was: %s' % (val, self,))
        print('*** TEST FAILED ***')
        return False

    def is_error(self):
        """ Assert that the compile failed, but *not* with an
        "increase $SETTING" error.
        """
        if (self.status == Result.ERROR and not self.memsetting):
            return True
        error('Should be error, but was: %s' % (self,))
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
    
def error(msg):
    """Note an error in the global error list.
    """
    errorlist.append( (testname, msg) )


# And now, the tests themselves.

def run_checksum_test():
    # The source files tested here must have an explicit serial-number
    # directive.

    res = compile('minimal_test.inf')
    res.is_ok(md5='666ad5e11db0afa6d225f24791624962')

    res = compile('minimal_test.inf', zversion=3)
    res.is_ok(md5='f8f4e05e92eadfec061042a8d4a510c0')

    res = compile('minimal_test.inf', zversion=4)
    res.is_ok(md5='bc43c06935ea63433df869c71e56202a')

    res = compile('minimal_test.inf', zversion=5)
    res.is_ok(md5='666ad5e11db0afa6d225f24791624962')

    res = compile('minimal_test.inf', zversion=6)
    res.is_ok(md5='6364e3d4aff3545c1d42841a1eb9333d')

    res = compile('minimal_test.inf', zversion=7)
    res.is_ok(md5='9e1e6e9c0d579348d06467e542e7a650')

    res = compile('minimal_test.inf', zversion=8)
    res.is_ok(md5='0bf834ecb4c66f818414b3525cc0e27a')

    res = compile('minimal_test.inf', glulx=True)
    res.is_ok(md5='db5cf5fb15fc67f08a4c629ed6cfaf78')
    
    res = compile('i7-min-6G60.inf')
    res.is_ok(md5='3a33dcf5d927a3675bd0db240e366076')

    res = compile('i7-min-6G60.inf', zversion=8)
    res.is_ok(md5='419a9fa355a5099263420fc9a2b38258')

    res = compile('i7-min-6G60.inf', glulx=True)
    res.is_ok(md5='1a5566218d96adcf497476796fd73e60')

    res = compile('Advent.inf', includedir='i6lib-611')
    res.is_ok(md5='945c30f435dc6ae049a2af32280adfff')

    res = compile('Advent.inf', includedir='i6lib-611', zversion=8)
    res.is_ok(md5='ef279fbcc579820781f186d2717ad4bb')

    res = compile('Advent.inf', includedir='i6lib-611', glulx=True)
    res.is_ok(md5='9221642842d97ceec2137bab646c82b6')

    
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
    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':4000})
    res.is_memsetting('MAX_SYMBOLS')

    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10035})
    res.is_memsetting('MAX_SYMBOLS')

    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10036})
    res.is_ok()
    
    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':4000}, glulx=True)
    res.is_memsetting('MAX_SYMBOLS')

    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10049}, glulx=True)
    res.is_memsetting('MAX_SYMBOLS')

    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10050}, glulx=True)
    res.is_ok()


def run_symbols_chunk_size():
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 800, 'MAX_SYMBOLS':10036})
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1000, 'MAX_SYMBOLS':10036})
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1001, 'MAX_SYMBOLS':10036})
    res.is_ok()
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1600, 'MAX_SYMBOLS':10036})
    res.is_ok()
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 800, 'MAX_SYMBOLS':10050}, glulx=True)
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1000, 'MAX_SYMBOLS':10050}, glulx=True)
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1001, 'MAX_SYMBOLS':10050}, glulx=True)
    res.is_ok()

    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1600, 'MAX_SYMBOLS':10050}, glulx=True)
    res.is_ok()

    # Distinct case: a single symbol overrunning the chunk size
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE':20})
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')


def run_max_objects():
    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':200})
    res.is_memsetting('MAX_OBJECTS')

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':523})
    res.is_memsetting('MAX_OBJECTS')

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':524})
    res.is_ok()

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':200}, glulx=True)
    res.is_memsetting('MAX_OBJECTS')

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':523}, glulx=True)
    res.is_memsetting('MAX_OBJECTS')

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':524}, glulx=True)
    res.is_ok()


def run_max_classes():
    res = compile('max_classes_test.inf', memsettings={'MAX_CLASSES':73})
    res.is_memsetting('MAX_CLASSES')

    res = compile('max_classes_test.inf', memsettings={'MAX_CLASSES':74})
    res.is_ok()

    res = compile('max_classes_test.inf', memsettings={'MAX_CLASSES':73}, glulx=True)
    res.is_memsetting('MAX_CLASSES')

    res = compile('max_classes_test.inf', memsettings={'MAX_CLASSES':74}, glulx=True)
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


def run_alloc_chunk_size():
    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':150})
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':300})
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':611})
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':612})
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':613})
    res.is_ok()

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':16384})
    res.is_ok()

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':256}, glulx=True)
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':914}, glulx=True)
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':915}, glulx=True)
    res.is_memsetting('ALLOC_CHUNK_SIZE')

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':916}, glulx=True)
    res.is_ok()

    res = compile('static_text_test.inf', memsettings={'ALLOC_CHUNK_SIZE':32768}, glulx=True)
    res.is_ok()

    ### Many more tests should be done here.


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


def run_max_expression_nodes():
    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':42})
    res.is_memsetting('MAX_EXPRESSION_NODES')
    
    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':43})
    res.is_ok()

    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':42}, glulx=True)
    res.is_memsetting('MAX_EXPRESSION_NODES')
    
    res = compile('max_expression_nodes_test.inf', memsettings={'MAX_EXPRESSION_NODES':43}, glulx=True)
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
    res.is_ok(md5='02220381cf4d5e91789491a738625b91')

    res = compile('i7-min-6G60.inf', memsettings={'OMIT_UNUSED_ROUTINES':1}, glulx=True)
    res.is_ok()
    res.is_ok(md5='44dfeda31294f553e6a743eab614b7fb')


test_catalog = [
    ('CHECKSUM', run_checksum_test),
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
    ('ALLOC_CHUNK_SIZE', run_alloc_chunk_size),
    ('MAX_NUM_STATIC_STRINGS', run_max_num_static_strings),
    ('MAX_QTEXT_SIZE', run_max_qtext_size),
    ('MAX_STATIC_STRINGS', run_max_static_strings),
    ('MAX_LOW_STRINGS', run_max_low_strings),
    ('MAX_VERB_WORD_SIZE', run_max_verb_word_size),
    ('MAX_EXPRESSION_NODES', run_max_expression_nodes),
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
        error('No such test!')
        continue
    func()
    
print()

if (not errorlist):
    print('All tests passed.')
else:
    print('%d errors!' % (len(errorlist),))
    for (test, msg) in errorlist:
        print('  %s: %s' % (test, msg))

