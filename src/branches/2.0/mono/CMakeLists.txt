INCLUDE_DIRECTORIES(${COMO_SOURCE_DIR}/include)

# Compile C# code

ADD_CUSTOM_TARGET(como-csharp ALL DEPENDS "como.dll")
ADD_CUSTOM_COMMAND(
        OUTPUT como.dll
        COMMAND ${MONO_MCS} -out:${COMO_BINARY_DIR}/mono/como.dll
            -target:library ${COMO_SOURCE_DIR}/mono/como.cs
        MAIN_DEPENDENCY ${COMO_SOURCE_DIR}/mono/como.cs
)
