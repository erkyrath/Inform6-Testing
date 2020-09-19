## Inform 6 compiler tests

This script runs the Inform 6 compiler many times, testing for various
problems such as overflow conditions. It also compiles a bunch of
known source files, making sure that the generated game files are
exactly as expected. ("Exactly" excludes serial number, since that can
change between compiles, and the compiler version number, since we
might want to run this on older version of Inform.)

The tests should always be in sync with the latest version (not the
latest *released* version!) of the I6 compiler source:
https://github.com/DavidKinder/Inform6

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

Historical note: I started writing these tests in 2011, as part of a
general cleanup of the compiler code. (Thanks to Daniel Fremont for
the many bug reports uncovered by his input-fuzzing project.) The
tests lived in an unmerged branch of my fork of the Inform repository.
You could find them on github, but you had to know where to look.

In 2020, I decided to split the tests off as a separate repository. I
also added the checksum tests. These validate our
(already-established) policy that I6 compiler changes should be as
binary-compatible as possible. That is, compiling valid I6 source with
a newer version of the compiler should produce *the same game file* if
we can possibly manage it.

(Of course, if we fix a code generation bug, then the compiler output
will change. But if we add a new compiler feature, it will be opt-in.)

### License

The runtest.py script and the test scripts are released under the MIT
license, except as noted below:

- Inform 6/11 library (i6lib-611): Artistic license
  https://gitlab.com/DavidGriffith/inform6lib

- MetroCenter '84 library and Cloak of Darkness port (cloak-metro84-v3test.inf): Artistic license
  https://github.com/ByteProject/Metrocenter84

- PunyInform 1.6 (punylib-16) and Library of Horror (library_of_horror.inf): MIT license
  https://github.com/johanberntsson/PunyInform
