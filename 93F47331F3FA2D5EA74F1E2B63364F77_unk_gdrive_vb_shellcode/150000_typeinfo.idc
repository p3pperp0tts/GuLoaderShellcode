//


#define UNLOADED_FILE   1
#include <idc.idc>

static main(void)
{
  Enums();              // enumerations
  Structures();         // structure types
  ApplyStrucTInfos();
	set_inf_attr(INF_LOW_OFF, 0x150000);
	set_inf_attr(INF_HIGH_OFF, 0x156000);
}

//------------------------------------------------------------------------
// Information about enum types

static Enums(void) {
        auto id;
        begin_type_updating(UTP_ENUM);
        end_type_updating(UTP_ENUM);
}

//------------------------------------------------------------------------
// Information about type information for structure members

static ApplyStrucTInfos() {
}

//------------------------------------------------------------------------
// Information about structure types

static Structures(void) {
        auto id;
        begin_type_updating(UTP_STRUCT);
        end_type_updating(UTP_STRUCT);
}

// End of file.
