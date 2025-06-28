#pragma once
#include "Structure.hpp"


#define LUAU_COMMA_SEP ,
#define LUAU_SEMICOLON_SEP ;

#define LUAU_COMMA_SEP ,
#define LUAU_SEMICOLON_SEP ;

#define LUAU_SHUFFLE3( sep, a1, a2, a3 ) a3 sep a1 sep a2
#define LUAU_SHUFFLE4( sep, a1, a2, a3, a4 ) a1 sep a4 sep a2 sep a3
#define LUAU_SHUFFLE5( sep, a1, a2, a3, a4, a5 ) a3 sep a5 sep a4 sep a2 sep a1
#define LUAU_SHUFFLE6( sep, a1, a2, a3, a4, a5, a6 ) a2 sep a4 sep a3 sep a1 sep a5 sep a6
#define LUAU_SHUFFLE7( sep, a1, a2, a3, a4, a5, a6, a7 ) a4 sep a7 sep a2 sep a3 sep a1 sep a6 sep a5
#define LUAU_SHUFFLE8( sep, a1, a2, a3, a4, a5, a6, a7, a8 ) a6 sep a4 sep a7 sep a2 sep a8 sep a1 sep a5 sep a3
#define LUAU_SHUFFLE9( sep, a1, a2, a3, a4, a5, a6, a7, a8, a9 ) a4 sep a5 sep a9 sep a8 sep a7 sep a6 sep a1 sep a3 sep a2


#define PROTO_MEMBER1_ENC VMValue0
#define PROTO_MEMBER2_ENC VMValue1
#define PROTO_DEBUGISN_ENC VMValue2
#define PROTO_TYPEINFO_ENC VMValue3
#define PROTO_DEBUGNAME_ENC VMValue4

#define LSTATE_STACKSIZE_ENC VMValue3
#define LSTATE_GLOBAL_ENC VMValue0

#define CLOSURE_FUNC_ENC VMValue0
#define CLOSURE_CONT_ENC VMValue2
#define CLOSURE_DEBUGNAME_ENC VMValue1

#define TABLE_MEMBER_ENC VMValue0
#define TABLE_META_ENC VMValue0

#define UDATA_META_ENC VMValue2

#define TSTRING_HASH_ENC VMValue4
#define TSTRING_LEN_ENC VMValue0

#define GSTATE_TTNAME_ENC VMValue0
#define GSTATE_TMNAME_ENC VMValue0