cmake_minimum_required(VERSION 3.5)
PROJECT (FSS)
ADD_EXECUTABLE(fss utils.c block.c)
TARGET_COMPILE_OPTIONS(fss PUBLIC -maes)
TARGET_LINK_LIBRARIES(fss ssl crypto)

ADD_EXECUTABLE(fssgen fssgen.c block.c b64.c)
TARGET_COMPILE_OPTIONS(fssgen PUBLIC -maes)
TARGET_LINK_LIBRARIES(fssgen ssl crypto)

ADD_EXECUTABLE(fsseval fsseval.c block.c b64.c)
TARGET_COMPILE_OPTIONS(fsseval PUBLIC -maes)
TARGET_LINK_LIBRARIES(fsseval ssl crypto)
