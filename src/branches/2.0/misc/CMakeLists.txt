# $Id$
INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/misc)

SET(STRUCTMAGIC_SRC
  gen-csclass.c
  gen-csglue.c
  gen-serial.c
  structmagic.c
  ${COMO_BINARY_DIR}/misc/lexer.c
  ${COMO_BINARY_DIR}/misc/grammar.c
)

#
# Command to generate both grammar.c and grammar.h.
# We don't add grammar.h as an explicit output, but
# the flex command, which in fact depends on grammar.h,
# has been made depend on grammar.c to make sure an
# updated grammar.h has been generated.
#
ADD_CUSTOM_COMMAND(
    OUTPUT ${COMO_BINARY_DIR}/misc/grammar.c
    COMMAND ${BISON_EXECUTABLE} -d ${COMO_SOURCE_DIR}/misc/grammar.y
        --output-file ${COMO_BINARY_DIR}/misc/grammar.c
    MAIN_DEPENDENCY ${COMO_SOURCE_DIR}/misc/grammar.y
    WORKING_DIRECTORY ${COMO_BINARY_DIR}/misc
)

#
# Command to run flex.
#
ADD_CUSTOM_COMMAND(
    OUTPUT ${COMO_BINARY_DIR}/misc/lexer.c
    COMMAND flex -t ${COMO_SOURCE_DIR}/misc/lexer.l > lexer.c
    MAIN_DEPENDENCY ${COMO_SOURCE_DIR}/misc/lexer.l

    # XXX dependency hack
    #DEPENDS ${COMO_BINARY_DIR}/misc/tokens.h
    DEPENDS ${COMO_BINARY_DIR}/misc/grammar.c

    WORKING_DIRECTORY ${COMO_BINARY_DIR}/misc
)

#
# Some versions of flex (at least 2.5.33) produce code with comparisons between
# signed and unsigned vars. This, combined with -Wall and -Werror, prevents CoMo
# from building. We add -Wno-sign-compare to gcc flags to work around this.
# (see bug #1468610 for the flex project at http://sf.net/projects/flex)
#
# We also add -Wno-unused because apparently under certain circumstances
# not every emitted function will be used.
#
SET_SOURCE_FILES_PROPERTIES(lexer.c COMPILE_FLAGS "-Wno-sign-compare -Wno-unused")

#
# Also relax warnings for bison generated files
#
SET_SOURCE_FILES_PROPERTIES(grammar.c COMPILE_FLAGS "-Wno-sign-compare -Wno-unused")

ADD_EXECUTABLE(structmagic ${STRUCTMAGIC_SRC})

