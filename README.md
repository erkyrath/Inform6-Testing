## Inform 6 compiler tests

This script runs the Inform 6 compiler many times, testing for various
problems such as overflow conditions. It also compiles a bunch of known
source files, making sure that the generated game files are exactly as
expected.

I use this for regression testing of the compiler during development.
Note that the script does not *run* the compiled game files. That's
a different problem.

The I6 source files are in the src directory. The script assumes that
there's a usable Inform binary in the current directory. (If not,
supply the `--binary` argument.)

To run:

    python3 runtest.py [ --binary INFORM ] [ TESTS... ]

If you don't name a test, it will run every test.

This currently works on MacOSX only. It uses the "libgmalloc" debugging
library available on OSX. (Type "man libgmalloc".) It could be adapted
to other debugging-malloc libraries, but you'd have to adjust the
magic environment variables, and maybe the stderr parsing.
