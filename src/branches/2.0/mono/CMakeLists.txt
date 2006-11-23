INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

# Compile C# code

SET(COMO_DLL ${COMO_BINARY_DIR}/mono/como.dll)

ADD_CUSTOM_TARGET(como-csharp ALL DEPENDS ${COMO_DLL})
ADD_CUSTOM_COMMAND(
        OUTPUT ${COMO_DLL}
        COMMAND ${MONO_MCS} -out:${COMO_DLL}
            -target:library ${COMO_SOURCE_DIR}/mono/como.cs
        MAIN_DEPENDENCY ${COMO_SOURCE_DIR}/mono/como.cs
)
