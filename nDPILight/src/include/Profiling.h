#ifndef NDPILIGHT_PROFILING_H
#define NDPILIGHT_PROFILING_H

#include "ndpi_light_includes.h"


#define PROFILING_DECLARE(n) \
        ticks __profiling_sect_start[n]; \
        const char *__profiling_sect_label[n]; \
        ticks __profiling_sect_tot[n]; \
        u_int64_t __profiling_sect_counter[n];
#define PROFILING_INIT() memset(__profiling_sect_tot, 0, sizeof(__profiling_sect_tot)), memset(__profiling_sect_label, 0, sizeof(__profiling_sect_label)), memset(__profiling_sect_counter, 0, sizeof(__profiling_sect_counter))
#define PROFILING_SECTION_ENTER(l,i) __profiling_sect_start[i] = getticks(), __profiling_sect_label[i] = l, __profiling_sect_counter[i]++
#define PROFILING_SECTION_EXIT(i)    __profiling_sect_tot[i] += getticks() - __profiling_sect_start[i]
#define PROFILING_NUM_SECTIONS (sizeof(__profiling_sect_tot)/sizeof(ticks))
#define PROFILING_SECTION_AVG(i,n) (__profiling_sect_tot[i] / (n + 1))
#define PROFILING_SECTION_TICKS(i) (__profiling_sect_tot[i] / (__profiling_sect_counter[i] + 1))
#define PROFILING_SECTION_LABEL(i) __profiling_sect_label[i]

#endif
