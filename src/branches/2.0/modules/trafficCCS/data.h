#include "como.h"

como_tuple como_record struct traffic_record {
    timestamp_t ts;
    uint64_t    bytes[2];
    uint32_t    pkts[2];
};

como_config struct config {
    int meas_ivl;	/* measurement interval */
    int iface;		/* interface */
};

//typedef struct config config_t;

