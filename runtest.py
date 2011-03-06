#!/usr/bin/env python

# This script runs the Inform 6 compiler many times, testing for memory
# overflow conditions. It uses the I6 source files in this directory.
# It also assumes that there's a usable Inform binary in the parent
# directory. (If not, adjust the informbinary variable below.)
#
# To run: "python runtest.py".
#
# This currently works on MacOSX only. It uses the "libgmalloc" debugging
# library available on OSX. (Type "man libgmalloc".) It could be adapted
# to other debugging-malloc libraries, but you'd have to adjust the
# magic environment variables, and maybe the stderr parsing.
#
# This currently only tests two memory settings: MAX_SYMBOLS and
# SYMBOLS_CHUNK_SIZE. (Really, SYMBOLS_CHUNK_SIZE is testing for *low*
# values.) Feel free to expand it.

import os
import re
import signal
import subprocess

informbinary = '../inform'

testname = '???'
errorlist = []

def set_testname(val):
    global testname
    testname = val
    print
    print '* Test:', testname
    print
    
def compile(srcfile, glulx=False, memsettings={}):
    argls = [ informbinary ]
    if (glulx):
        argls.append('-G')
    for (key, val) in memsettings.items():
        argls.append('$%s=%s' % (key, val))
    argls.append('-w')
    argls.append(srcfile)
    print 'Running:', ' '.join(argls)

    env = dict(os.environ)
    env['DYLD_INSERT_LIBRARIES'] = '/usr/lib/libgmalloc.dylib'
    env['MALLOC_WORD_SIZE'] = '1'
    #env['MALLOC_PROTECT_BEFORE'] = '1'
    
    run = subprocess.Popen(argls, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = run.wait()
    stdout = run.stdout.read()
    stderr = run.stderr.read()
    res = Result(res, stdout, stderr)

    print '...%s' % (res,)
    return res

def error(msg):
    errorlist.append( (testname, msg) )

class Result:
    SIGNAL = 'signal'
    OK = 'ok'
    ERROR = 'error'
    
    def __init__(self, retcode, stdout, stderr):
        self.status = None
        self.signame = None
        self.warnings = 0
        self.errors = 0
        self.memsetting = None
        
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
                if ('GuardMalloc[' in ln):
                    error('Apparent libgmalloc error ' + ln)
            
            lines = stdout.split('\n')
            outlines = 0
            for ln in lines:
                
                match = re.match('line (\d+): Fatal error:', ln)
                if (match):
                    outlines += 1
                    self.errors = 1
                    ln = ln[ match.end() : ].strip()
                    match = re.match('The memory setting (\S+)', ln)
                    if (match):
                        self.memsetting = match.group(1)
                    continue
                
                match = re.match('Compiled with (\d+) errors? \(no outout\)', ln)
                if (match):
                    outlines += 1
                    self.errors = int(match.group(1))
                    continue
                
                match = re.match('Compiled with (\d+) errors? and (\d+) suppressed warnings? \(no outout\)', ln)
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

    def is_ok(self):
        if (self.status == Result.OK):
            return True
        error('Should be ok, but was: %s' % (self,))
        print '...TEST FAILED'
        return False

    def is_memsetting(self, val):
        if (self.status == Result.ERROR and self.memsetting == val):
            return True
        error('Should be error (%s), but was: %s' % (val, self,))
        print '...TEST FAILED'
        return False

def run_max_symbols():
    set_testname('MAX_SYMBOLS')
    
    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10035})
    res.is_memsetting('MAX_SYMBOLS')

    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10036})
    res.is_ok()
    
    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10041}, glulx=True)
    res.is_memsetting('MAX_SYMBOLS')

    res = compile('max_symbols_test.inf', memsettings={'MAX_SYMBOLS':10042}, glulx=True)
    res.is_ok()

def run_symbols_chunk_size():
    set_testname('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 800, 'MAX_SYMBOLS':10036})
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1600, 'MAX_SYMBOLS':10036})
    res.is_ok()
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 800, 'MAX_SYMBOLS':10042}, glulx=True)
    res.is_memsetting('SYMBOLS_CHUNK_SIZE')
    
    res = compile('max_symbols_test.inf', memsettings={'SYMBOLS_CHUNK_SIZE': 1600, 'MAX_SYMBOLS':10042}, glulx=True)
    res.is_ok()
    
def run_max_objects():
    set_testname('MAX_OBJECTS')
    
    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':523})
    res.is_memsetting('MAX_OBJECTS')

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':524})
    res.is_ok()

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':523}, glulx=True)
    res.is_memsetting('MAX_OBJECTS')

    res = compile('max_objects_test.inf', memsettings={'MAX_OBJECTS':524}, glulx=True)
    res.is_ok()

def run_all_tests():
    run_max_symbols()
    run_symbols_chunk_size()
    run_max_objects()
    
#run_all_tests()
run_max_objects()

print

if (not errorlist):
    print 'All tests passed.'
else:
    print '%d errors!' % (len(errorlist),)
    for (test, msg) in errorlist:
        print '  %s: %s' % (test, msg)

