## Inform 6 compiler tests

This script runs the Inform 6 compiler many times, testing for various
problems such as overflow conditions. It also compiles a bunch of
known source files, making sure that the generated game files are
exactly as expected. ("Exactly" excludes serial number, since that can
change between compiles, and the compiler version number, since we
might want to run this on older version of Inform.) It can also *run*
the generated game files and check the game output against known
samples.

The tests should always be in sync with the latest version (not the
latest *released* version!) of the I6 compiler source:
https://github.com/DavidKinder/Inform6

The I6 source files are in the `src` directory. The script assumes that
there's a usable Inform binary in the current directory. (If not,
supply the `--binary` argument.)

To run:

    python3 runtest.py [ TESTS... ]

Test names can be groups (`LEXER`, `STATEMENTS`, etc) or source
filenames (`Advent.inf`) or filename glob patterns (`unused*`,
`*header.inf`, `*6G60*`). Use the `--list` option to see a list of
groups.

If you don't name a test, it will run every test.

The `--reg` argument tells the script to execute game files and validate
their output against the scripts in the `reg` directory. This option
assumes that RemGlk interpreters named `bocfelr` and `glulxer` are in
your `$PATH`, and a script called `regtest` is in the current directory.
The `regtest` script should invoke [regtest.py][], perhaps like this:

[regtest.py]: https://github.com/erkyrath/plotex/blob/master/regtest.py

```
#!/bin/bash
python3 regtest.py "$@"
```

The test framework tries to use a strict malloc library to detect memory
errors. However, this feature currently works on MacOSX only. It uses the
"libgmalloc" debugging library available on OSX. (Type "man libgmalloc".)
It could be adapted to other debugging-malloc libraries, but you'd have to
adjust the magic environment variables, and maybe the stderr parsing.

### Argument reference

- `--reg`: Run game execution tests.
- `--binary`: Path to the Inform 6 binary
- `--regtest`: Path to the `regtest` script

### Historical note

I started writing these tests in 2011, as part of a general cleanup of
the compiler code. (Thanks to Daniel Fremont for the many bug reports
uncovered by his input-fuzzing project.) The tests lived in an unmerged
branch of my fork of the Inform repository. You could find them on github,
but you had to know where to look.

In 2020, I decided to split the tests off as a separate repository. I
also added the checksum tests. These validate our
(already-established) policy that I6 compiler changes should be as
binary-compatible as possible. That is, compiling valid I6 source with
a newer version of the compiler should produce *the same game file* if
we can possibly manage it.

(Of course, if we fix a code generation bug, then the compiler output
will change. That's when we use the `--reg` option to verify game output.
But if we add a new compiler feature, it should be opt-in and only change
game files when specifically requested.)

### License

The runtest.py script and the test scripts are released under the MIT
license, except as noted below:

- Inform 6/11 library (i6lib-611): Artistic license
  https://gitlab.com/DavidGriffith/inform6lib

- MetroCenter '84 library and Cloak of Darkness port (cloak-metro84-v3test.inf): Artistic license
  https://github.com/ByteProject/Metrocenter84

- PunyInform (punylib-16/36) and Library of Horror (library_of_horror-16/36.inf): MIT license
  https://github.com/johanberntsson/PunyInform
